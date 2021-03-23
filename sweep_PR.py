#!/usr/bin/env python
"""This script is based on the LCG/SFT sweep_MR from
https://gitlab.cern.ch/sft/lcgcmake
which in turn is based on the ATLAS MR sweeper from
https://gitlab.cern.ch/atlas-sit/librarian


It can be used to automatically create pull requests to other branches based on existing merge
commits. For example to backport fixes to a list of branches chosen by the "alsoTargeting:<Branch>"
label.

"""

import argparse
import logging
import os
import re
import subprocess
import sys
from pprint import pformat
import yaml

import github
from github.GithubException import GithubException


def execute_command_with_retry(cmd, max_attempts=1, logger=logging):
  logger.debug('working directory: %s', os.getcwd())
  logger.debug("running command '%s' with max attempts %d", cmd, max_attempts)
  attempt = 0
  while attempt < max_attempts:
    attempt += 1
    logger.debug('running attempt %d', attempt)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = process.communicate()
    status = process.returncode
    out = out.strip().decode()
    err = err.strip().decode()
    logger.debug('command returned %d', status)
    if out:
      logger.debug('stdout:')
      for line in out.splitlines():
        logger.debug('  ' + line)
    if err:
      logger.debug('stderr:')
      for line in err.splitlines():
        logger.debug('  ' + line)

    # break loop if execution was successful
    if status == 0:
      break

  return status, out, err


def list_changed_packages(pr):
  """
  See if this can be useful to automatically determine target branches based on changed files

  pr ... Github pull request object

  return: list of packages
  """
  changed_files = set([c[p] for c in pr.changes()['changes'] for p in ['old_path', 'new_path']])
  logging.debug("changed files:\n%s", pformat(changed_files, indent=20))
  return []


def get_sweep_target_branch_rules(src_branch):
  git_cmd = "git show {0}:Sweep/config.yaml".format(src_branch)
  status, out, _ = execute_command_with_retry(git_cmd)

  # bail out in case of errors
  if status != 0:
    logging.critical("failed to retrieve CI configuration")
    return None

  try:
    CI_config = yaml.safe_load(out)
  except Exception:
    logging.critical("failed to interpret the following text as YAML:\n%s", out)
    return None
  if CI_config is None:
    logging.warning("empty Sweep/config.yaml in %s, hopefully you knew what you were doing.", src_branch)
    return None

  # get branch name without remote repository name
  branch_wo_remote = src_branch.split('/')[1]
  # make sure we have a valid sweeping configuration
  has_sweep_targets = 'sweep-targets' in CI_config
  has_targets_for_branch = has_sweep_targets and branch_wo_remote in CI_config['sweep-targets']
  has_target_rules = has_targets_for_branch and CI_config['sweep-targets'][branch_wo_remote]
  if not has_target_rules:
    return None

  target_branch_rules = CI_config['sweep-targets'][branch_wo_remote]
  logging.info("read %d sweeping rules for MRs to '%s", len(target_branch_rules), src_branch)
  logging.debug("sweeping rules: %r", target_branch_rules)

  return target_branch_rules


def get_list_of_merge_commits(branch, since, until):
  logging.info("looking for merge commits on '%s' since '%s'", branch, since)
  git_cmd = 'git log --merges --first-parent --oneline --since="{0}" --until="{1}" {2}'.format(since, until, branch)
  status, out, _ = execute_command_with_retry(git_cmd)

  # bail out in case of errors
  if status != 0:
    logging.critical("failed to retrieve merge commits")
    return None

  # extract hashes of merge commits
  hash_list = set()
  for line in out.split('\n'):
    # skip empty lines
    if not line:
      continue
    match = re.match(r"[0-9a-f]{6,}", line)
    if not match:
      logging.critical("could not extract merge commit hash from '%s'", line)
      continue
    hash_list.add(match.group())
  logging.info("found %d merge commits", len(hash_list))
  logging.debug("hashes : %s", repr(hash_list))

  return hash_list


def cherry_pick_mr(merge_commit, source_branch, target_branch_rules, repo, dry_run=False):
    # keep track of successful and failed cherry-picks
  logger = logging.getLogger('merge commit %s' % merge_commit)
  good_branches = set()
  failed_branches = set()

  # get merge commit object
  try:
    commit = repo.get_commit(merge_commit)
  except GithubException as e:
    logging.critical("failed to get merge commit '%s' with\n%s", merge_commit, e.data['message'])
    return

  # get pull request ID from commit message
  _, out, _ = execute_command_with_retry("git show {0}".format(merge_commit), logger=logger)
  match = re.search("Merge pull request #(\\d+)", out)
  if match:
    MR_IID = int(match.group(1))
    logger.debug("corresponds to PR ID %d", MR_IID)

    # retrieve github API object
    try:
      mr_handle = repo.get_pull(MR_IID)
    except GithubException:
      logger.critical("failed to retrieve Gitlab merge request handle")
      return
    else:
      logger.debug("retrieved Github pull request handle")
  else:
    logger.critical("failed to determine MR IID")
    return

  # save original author so that we can add as watcher
  original_mr_author = mr_handle.user.login
  logger.debug('original_mr_author: %s', original_mr_author)

  # handle sweep labels
  labels = set(label.name for label in pull.get_labels())
  for l in labels:
    logger.debug('label: %s', l)

  if "sweep:done" in labels:
    logger.info("was already swept -> skipping ......")
    return
  if "sweep:ignore" in labels:
    logger.info("is marked as ignore -> skipping .......")
    return

  target_branches = set()
  target_branches_exclude = set()

  logger.debug("Looking through PR labels .... ")

  for l in labels:
    logger.debug("label: %s", l)
    if re.match('^sweptFrom:', l):
      logger.info("contains %s label -> skipping to prevent sweeping it twice .......\n", l)
      return
    if re.match('^sweep:from ', l):
      _s_ = l.split(' ')
      if len(_s_) == 2:
        _ss_ = [_s_[1].encode('ascii', 'replace')]
        logger.info("was swept from branch: %s -> excluding %s from the target list", _ss_, _ss_)
        target_branches_exclude.update(_ss_)
    if re.match('^alsoTargeting:', l):
      _s_ = l.split(':')
      if len(_s_) == 2:
        _ss_ = [_s_[1]]
        logger.info("also targets the following branches: %s -> add to target list", _ss_)
        target_branches.update(_ss_)
      else:
        logger.warning("has empty 'alsoTargeting:' label -> ignore")

  # get list of affected packages for this MR
  affected_packages = list_changed_packages(mr_handle)
  logger.debug("MR %d affects the following packages: %r", gMR_IID, affected_packages)

  # determine set of target branches from rules and affected packages
  for rule, branches in target_branch_rules.items():
    # get pattern expression for affected packages
    pkg_pattern = re.compile(rule)
    # only add target branches if ALL affected packages match the given pattern
    matches = [pkg_pattern.match(pkg_name) for pkg_name in affected_packages]
    if matches and all(matches):
      logging.debug("add branches for rule '%s': %s", rule, branches)
      target_branches.update(branches)
    else:
      logging.debug("skip branches for rule '%s': %s", rule, branches)

  logger.info("MR %d is swept to %d branches: %r", MR_IID, len(target_branches), list(target_branches))

  if len(target_branches) == 0:
    labels.add("sweep:ignore")
    logger.debug("Zero target branches found, adding sweep:ignore label to the MR handle")
  else:
    labels.add("sweep:done")

  if dry_run:
    logger.debug("----- This is a test run, stop with this MR here ----")
    return

  mr_handle.labels = list(labels)
  mr_handle.save()

  # get initial MR commit title and description
  _, mr_title, _ = execute_command_with_retry('git show {0} --pretty=format:"%s"'.format(merge_commit))
  _, mr_desc, _ = execute_command_with_retry('git show {0} --pretty=format:"%b"'.format(merge_commit))

  _s_ = source_branch.split('/')
  if len(_s_) == 2:
    source_branch_strip = _s_[1]
  elif len(_s_) == 1:
    source_branch_strip = _s_[0]
  else:
    source_branch_strip = 'undefined branch'

  _comment_1_ = 'Sweeping !' + str(MR_IID) + ' from ' + source_branch_strip + ' to '
  _comment_2_ = '.\n' + mr_desc

  print(target_branches)
  for _t_ in target_branches:
    logger.debug("PR title for target branch %s: '%s'",_t_, _comment_1_ + _t_ + _comment_2_)

  # perform cherry-pick to all target branches
  for tbranch in target_branches:

    tbranch_excluded = False
    for t_excl in target_branches_exclude:
      if t_excl == tbranch:
        tbranch_excluded = True
        break
    if tbranch_excluded:
      logger.info("the PR originates from %s -> skip back sweep to %s", tbranch, tbranch)
      continue

    failed = False

    # create remote branch for containing the cherry-pick commit
    cherry_pick_branch = "cherry-pick-2-{0}-{1}".format(merge_commit, tbranch)
    try:
      repo.create_git_ref(ref='refs/heads/'+cherry_pick_branch, sha=repo.get_branch(tbranch).commit.sha)
    except GithubException as e:
      logger.critical("failed to create remote branch '%s' with\n%s", cherry_pick_branch, e.data['message'])
      failed = True
    else:
      # perform cherry-pick by merging
      try:
        # here this might be done better but don't find a better cherry-pick option !!!
        repo.merge(cherry_pick_branch,commit.sha,'cherry pick merge commit {0}'.format(commit.sha))
    except GithubException as e:
        logger.critical("failed to cherry pick merge commit, error: %s", e.data['message'])
        failed = True

    # only create MR if cherry-pick succeeded
    if failed:
      logger.critical("Failed to cherry-pick '%s' into '%s':"
                      "\n***** Hint: check merge conflicts on a local copy of this repository"
                      "\n**********************************************"
                      "\ngit checkout %s"
                      "\ngit cherry-pick -m 1 %s"
                      "\ngit status"
                      "\n**********************************************", merge_commit, tbranch, tbranch, merge_commit)
      failed_branches.add(tbranch)
    else:
      logger.info("cherry-picked '%s' into '%s'", merge_commit, tbranch)

      _title_ = _comment_1_ + tbranch + _comment_2_
      # create merge request
      mr_data = {}
      mr_data['source_branch'] = cherry_pick_branch
      mr_data['target_branch'] = tbranch
      mr_data['title'] = _title_
      mr_data['description'] = mr_desc
      mr_data['labels'] = ["sweep:from {0}".format(os.path.basename(source_branch))]
      mr_data['remove_source_branch'] = True
      logger.debug("Sweeping MR %d to %s with a title: '%s'",
                   MR_IID, tbranch, _title_)
      logger.debug("source_branch:%s: target_branch:%s: title:%s: descr:%s:",
                   mr_data['source_branch'],
                   mr_data['target_branch'],
                   mr_data['title'], mr_data['description'])
      for l in mr_data['labels']:
        logger.debug("label: %s", l)
      try:
        new_mr = project.mergerequests.create(mr_data)
      except GitlabCreateError as e:
        logger.critical("failed to create merge request for '%s' into '%s' with\n%s", cherry_pick_branch, tbranch, e.data['message'])
        failed_branches.add(tbranch)
      else:
        good_branches.add(tbranch)
        # adding original author as watcher
        notification_text = "Adding original author @{0:s} as watcher.".format(
            original_mr_author)
        new_mr.notes.create({'body': notification_text})

  # compile comment about sweep results
  if len(target_branches) > 0:
    comment = "**Sweep summary**\n"
    comment += "\nSweep ran in %s  " % os.environ.get('CI_JOB_URL', 'job_url')
    if good_branches:
      comment += "\nSuccessful:\n* " + "\n* ".join(sorted(good_branches)) + "\n"
    if failed_branches:
      comment += "\nFailed:\n* " + "\n* ".join(sorted(failed_branches))
      # add label to original MR indicating cherry-pick problem
      mr_handle.labels = list(set(mr_handle.labels) | {"sweep:failed"})
      mr_handle.save()

    # add sweep summary to MR in Gitlab
    try:
      mr_handle.notes.create({'body': comment})
    except GitlabCreateError as e:
      logger.critical(
          "failed to add comment with sweep summary with\n{0:s}".format(e.error_message))
  return


def main():
  parser = argparse.ArgumentParser(
      description="GitHub pull request sweeper",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument("-b", "--branch", required=True,
                      help="remote branch whose merge commits should be swept (e.g. origin/master)")
  parser.add_argument("-d", "--dry-run", dest="dry_run", action='store_true',
                      help="only perform a test run without actually modifying anything")
  parser.add_argument("-p", "--project-name", dest="project_name", required=True,
                      help="GitHub project with namespace (e.g. user/my-project)")
  parser.add_argument("-s", "--since", default="1 month ago",
                      help="start of time interval for sweeping MR (e.g. 1 week ago)")
  parser.add_argument("-t", "--token", required=True,
                      help="GitHub Personal Acess Token (PAT)")
  parser.add_argument("-u", "--until", default="now",
                      help="end of time interval for sweeping MR (e.g. 1 hour ago)")
  parser.add_argument(
      "-v",
      "--verbose",
      default="DEBUG",
      choices=[
          "DEBUG",
          "INFO",
          "WARNING",
          "ERROR",
          "CRITICAL"],
      help="verbosity level")
  parser.add_argument("--repository-root", dest="root", default=os.path.dirname(os.path.abspath(
      os.path.join(os.path.realpath(__file__), '../'))), help="path to root directory of git repository")

  # get command line arguments
  args = parser.parse_args()

  # configure log output
  logging.basicConfig(format='%(asctime)s %(name)-30s %(levelname)-10s %(message)s',
                      datefmt='%H:%M:%S',
                      level=logging.getLevelName(args.verbose),
                      stream=sys.stdout,
                      )

  logging.debug("parsed arguments:")
  for name, value in vars(args).items():
    logging.debug("    %12s : %s", name, value)

  if args.dry_run:
    logging.info("running in TEST mode")

  # we only support porting merge commits from remote branches since we expect
  # them to be created through the Github web interface
  # -> branch must contain the name of the remote repository (e.g. upstream/master)
  # -> infer it
  tokens = args.branch.split('/')
  if len(tokens) < 2:
    logging.critical("expect branch to specify a remote branch (e.g. 'upstream/master')")
    logging.critical("received branch '%s' which does not look like a remote branch", args.branch)
    logging.critical("--> aborting")
    sys.exit(1)

  # set name of remote repository
  args.remote_name = tokens[0]

  # get Github API handler
  gh = github.Github(args.token)
  try:
    # get Github project object
    repo = gh.get_repo(args.project_name)
    logging.debug("retrieved Github project handle")
  except GithubException as e:
    logging.critical("error communication with Github API '%s'", e.data['message'])
    sys.exit(1)

  # get top-level directory of git repository (specific to current directory structure)
  workdir = os.path.abspath(args.root)

  logging.info("changing to root directory of git repository '%s'", workdir)
  current_dir = os.getcwd()
  os.chdir(workdir)

  # fetch latest changes
  status, _, _ = execute_command_with_retry("git fetch --prune {0}".format(args.remote_name))
  if status != 0:
    logging.critical("failed to fetch from '%s'", args.remote_name)
    return None

  # get list of branches PRs should be forwarded to
  # this lets one set which branches to target based on changed files or other criteria
  # currently not used
  target_branch_rules = get_sweep_target_branch_rules(args.branch)
  if not target_branch_rules:
    logging.info("no sweeping rules for branch '%s' found", args.branch)
    target_branch_rules = {}

  # get list of MRs in relevant period
  MR_list = get_list_of_merge_commits(args.branch, args.since, args.until)
  if not MR_list:
    logging.info("no MRs to '%s' found in period from %s until %s", args.branch, args.since, args.until)
    sys.exit(0)

  # do the actual cherry-picking
  for mr in MR_list:
    logging.debug("")
    logging.debug("===== Next MR: %s ======", mr)
    cherry_pick_mr(mr, args.branch, target_branch_rules, repo, args.dry_run)

  # change back to initial directory
  os.chdir(current_dir)
  return None


if __name__ == "__main__":
  main()
