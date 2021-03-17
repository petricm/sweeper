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
                      help="private GitLab user token")
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
  # them to be created through the Gitlab web interface
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

  # get GitLab API handler
  gh = github.Github(args.token)
  try:
    # get Github project object
    repo = gh.get_repo(args.project_name)
    logging.debug("retrieved Github project handle")
  except GithubException as e:
    logging.critical("error communication with Gitlab API '%s'", e.data['message'])
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
  # target_branch_rules = get_sweep_target_branch_rules(args.branch)
  # if not target_branch_rules:
  #   logging.info("no sweeping rules for branch '%s' found", args.branch)
  #   target_branch_rules = {}
  #
  # # get list of MRs in relevant period
  # MR_list = get_list_of_merge_commits(args.branch, args.since, args.until)
  # if not MR_list:
  #   logging.info("no MRs to '%s' found in period from %s until %s",
  #                args.branch, args.since, args.until)
  #   sys.exit(0)
  #
  # # do the actual cherry-picking
  # for mr in MR_list:
  #   logging.debug("")
  #   logging.debug("===== Next MR: %s ======", mr)
  #   cherry_pick_mr(mr, args.branch, target_branch_rules,
  #                  project, args.dry_run)

  # change back to initial directory
  os.chdir(current_dir)
  return None


if __name__ == "__main__":
  main()
