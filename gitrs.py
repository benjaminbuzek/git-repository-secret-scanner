# GIT-RS Repository Scanner Runner
# Copyright (c) Benjamin Buzek

import os
import re
import sys
import math
import signal
import binascii
import datetime
import argparse

from git import *
from collections import Counter
from termcolor import colored


class GITRS:

    def __init__(self):
        self.APPNAME = colored("[GIT-RS]", "blue", attrs=["bold"])
        self.VERSION = "1.0"
        self.TITLE = " >>> 🐙 GIT-RS - Git Repository Scanner \n >>> Copyright (c) Benjamin Buzek"
        self.TITLE_VERSION = f" >>> Version {self.VERSION}" + "\n"

        self.FINDINGS = {}

    def description(self):
        """
        Print Scanner Description
        :return:
        """
        print(colored("    ________________    ____  _____", "blue", attrs=['bold']))
        print(colored("   / ____/  _/_  __/   / __ \/ ___/", "blue", attrs=['bold']))
        print(colored("  / / __ / /  / /_____/ /_/ /\__ ", "blue", attrs=['bold']))
        print(colored(" / /_/ // /  / /_____/ _, _/___/ /", "blue", attrs=['bold']))
        print(colored(" \____/___/ /_/     /_/ |_|/____/" + "\n", "blue", attrs=['bold']))
        print(colored(self.TITLE, "blue"))
        print(colored(self.TITLE_VERSION, "blue"))

    def get_arguments(self):
        """
        Get Scanner Arguments
        :return:
        """
        parser = argparse.ArgumentParser('gitrs-scanner.py',
                                         formatter_class=lambda prog: argparse.HelpFormatter(prog,
                                                                                             max_help_position=40))

        parser.add_argument('-r', '--repo',
                            help='Git repository to scan',
                            dest='repo',
                            required=True)

        parser.add_argument('-c', '--count',
                            help='Total number of commits to scan (default: all)',
                            dest='count',
                            default=sys.maxsize,
                            type=int)

        parser.add_argument('-e', '--entropy',
                            help='Min entropy (default: 4.5)',
                            dest='entropy',
                            default=4.5,
                            type=float)

        parser.add_argument('-l', '--length',
                            help='Max line length (default: 500)',
                            dest='length',
                            default=500,
                            type=int)

        parser.add_argument('-b', '--branch',
                            help='Branch to scan',
                            dest='branch')

        parser.add_argument('-v', '--verbose',
                            help='Verbose output',
                            dest='verbose',
                            action='store_true',
                            default=False)

        return parser.parse_args()

    def get_name(self):
        """
        Get Scanner Name
        :return:
        """
        return self.APPNAME

    def get_version(self):
        """
        Get Scanner Version
        :return:
        """
        return self.VERSION

    def get_ignored_files(self):
        """
        Get Ignored File Types
        :return:
        """
        with open("config/IGNORED_FILES", "r") as f:
            ignored_files = tuple(f.readlines())
        return ignored_files

    def get_ignored_extensions(self):
        """
        Get Ignored File Extensions
        :return:
        """
        with open("config/IGNORED_FILE_PREFIXES", "r") as f:
            ignored_extensions = tuple(f.readlines())
        return ignored_extensions

    def get_regex_patters(self):
        """
        Get Regex Patterns
        :return:
        """
        regexes_key, regexes_full = [], []
        # Search for these strings in the key string
        regexes_key.append(re.compile("[a-z]+/[a-z]+/[a-z]+/[a-z]+", re.IGNORECASE))  # Path
        regexes_key.append(re.compile("abcdef", re.IGNORECASE))  # Alphabet
        regexes_key.append(re.compile("[a-z]+[A-Z][a-z]+[A-Z[a-z]+[A-Z][a-zA-Z]+"))  # camelCase

        # Match against the full string
        regexes_full.append(re.compile("Subproject commit [a-f0-9]{40}"))  # Subproject commit
        regexes_full.append(re.compile("\"commit\": \"[a-f0-9]{40}\""))  # Commit message
        regexes_full.append(re.compile("publicKeyToken=\"[a-f0-9]{16}\""))  # .NET Public Key Token
        regexes_full.append(re.compile(".*[a-f0-9]{12,}\.(css|js)", re.IGNORECASE))  # CSS or JS filenames
        regexes_full.append(re.compile("[<>]{7} [a-f0-9]{40}", re.IGNORECASE))  # CSS or JS filenames
        return regexes_key, regexes_full

    def scanner_output(self, branch, findings, error=False):
        """
        Create Scanner Output
        :param branch:
        :param findings:
        :param error:
        :return:
        """
        with open(f'logs/gitrs_{datetime.datetime.now().strftime("%d-%m-%y_%H:%M:%S")}.log', 'w') as f:
            for sha, suspicious_commit in findings.items():
                suspicious_commit_path = f" {colored('Commit', 'green', attrs=['bold'])}\t{colored(':', 'green', attrs=['bold'])} {branch}@{sha}"
                suspicious_commit_date = f" {colored('Date', 'green', attrs=['bold'])}\t{colored(':', 'green', attrs=['bold'])} {suspicious_commit.date}"
                suspicious_commit_author = f" {colored('Author', 'green', attrs=['bold'])}\t{colored(':', 'green', attrs=['bold'])} {suspicious_commit.author}"
                print("\n")
                print(suspicious_commit_path)
                print(suspicious_commit_date)
                print(suspicious_commit_author)
                f.write(f" Commit\t: {branch}@{sha}" + "\n")
                f.write(f" Date\t: {suspicious_commit.date}" + "\n")
                f.write(f" Author\t: {suspicious_commit.author}" + "\n")
                for path in suspicious_commit.paths:
                    if "github.com" in self.get_arguments().repo.lower():
                        url = self.get_arguments().repo + "/blob/" + sha + "/" + path
                        print(f" {url}")
                        f.write(f" {url}\n")
                    else:
                        print(" " + path)
                        f.write(path)
                    for key, full in suspicious_commit.get_items(path):
                        print(colored(" + ", "red") + full)
                        f.write(" + " + full + "\n")
                f.write("\n")
            if error:
                sys.exit(1)
            else:
                sys.exit(0)

    def scanner_commit_entropy(self, data):
        """
        Get Commit Message Entropy
        :param data:
        :return:
        """
        if len(data) <= 1:
            return 0
        p, lns = Counter(data), float(len(data))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

    def scanner(self, repo, branch, commit_id):
        """
        Scan given Git Repository
        :param repo:
        :param branch:
        :param commit_id:
        :return:
        """
        key_strings_found = []
        scanned_commits = []

        ignored_files = self.get_ignored_files()
        ignored_extensions = self.get_ignored_extensions()

        regexes_key, regexes_full = self.get_regex_patters()

        prev_commit = None

        # number of total scanned commit messages
        n_commits = sum(1 for i in repo.iter_commits(branch, max_count=self.get_arguments().count)) - 1

        print(f" {self.APPNAME} Scanning branch\n", end="", flush=True)

        for commit_id, commit in enumerate(repo.iter_commits(branch, max_count=self.get_arguments().count)):

            if sys.stdout.isatty():
                current_progress = colored(str(commit_id), 'red', attrs=['bold'])
                total_progress = colored('/' + str(n_commits), 'red', attrs=['bold'])
                print(f" {self.APPNAME} Scanned commit messages\t{current_progress}{total_progress} in {str(branch)}\r",
                      end="",
                      flush=True)

            if not prev_commit:
                prev_commit = commit
                continue

            commit_sha = prev_commit.hexsha
            if commit_sha in scanned_commits:
                prev_commit = commit
                continue

            prev_commit_diff = commit.diff(prev_commit)
            commit_author = commit.author
            commit_date = commit.authored_date

            for difference in prev_commit_diff:
                path = difference.a_path

                if path.lower().endswith(ignored_extensions) or path.lower().endswith(ignored_files):
                    continue

                diff_message = commit.diff(prev_commit, create_patch=True, paths=path)

                for diff_message_body in diff_message:
                    try:
                        diff_message_body_lines = diff_message_body.diff.decode("utf-8").split("\n")
                    except UnicodeDecodeError:
                        diff_message_body_lines = str(diff_message_body.diff).split("\n")

                    for line in diff_message_body_lines:
                        # check if commit contains changes, otherwise
                        # continue with next commit
                        if not line.startswith("+"):
                            continue
                        matches = re.findall("((^|\n).*?([a-zA-Z0-9+/=]{16,}|[A-Fa-f0-9]{12,).*?($|\n))", line[1:])

                        for match in matches:
                            full_string = match[0].lstrip()
                            key_string = match[2]

                            # long strings are likely to be embedded files
                            if len(full_string) > self.get_arguments().length:
                                continue

                            commit_entropy = self.scanner_commit_entropy(key_string)

                            # check key_string for hexadecimal
                            try:
                                binascii.unhexlify(key_string)
                                # adjust entropy since key_string is hex
                                commit_entropy += 1.3
                            except ValueError:
                                pass

                            if commit_entropy > self.get_arguments().entropy:
                                # ignore common / seen patterns
                                if key_string in key_strings_found:
                                    continue
                                # check against regexes of boring patterns to include
                                matched = False
                                for regex in regexes_key:
                                    if re.search(regex, key_string):
                                        matched = True
                                        break
                                if not matched:
                                    for regex in regexes_full:
                                        if re.match(regex, full_string):
                                            matched = True
                                            break
                                if matched:
                                    continue

                                key_strings_found.append(key_string)
                                if self.get_arguments().verbose:
                                    inserted = colored("\u251c\u2500", "blue")
                                    print(
                                        f"  {inserted}{self.APPNAME} Entropy: {commit_entropy}\t Key String: {key_string}")

                                # Add the commit if it doesn't exist
                                if not commit_sha in self.FINDINGS:
                                    self.FINDINGS[commit_sha] = Commit(commit_sha, commit_author, commit_date, branch)
                                if self.FINDINGS[commit_sha].get_path(path):
                                    self.FINDINGS[commit_sha].add_item(path, key_string, full_string)
                                else:
                                    self.FINDINGS[commit_sha].add_path(path)
                                    self.FINDINGS[commit_sha].add_item(path, key_string, full_string)
            prev_commit = commit
            scanned_commits.append(commit_sha)

        return self.FINDINGS

    def run(self):
        """
        Run Scanner
        :return:
        """
        self.description()

        try:
            repository = "target/" + self.get_arguments().repo.rsplit("/", 1)[1]
        except IndexError:
            repository = "target/" + self.get_arguments().repo

        if os.path.isdir(repository):
            try:
                repo = Repo(repository)
                print(f" {self.APPNAME} Loaded repository\t\tfrom \"{repository}\"")
            except NoSuchPathError:
                print(f" {self.APPNAME} Invalid repository\t\t{repository}")
                sys.exit(1)
        else:
            try:
                print(
                    f" {self.APPNAME} Trying to clone repository\t\tfrom \"{self.get_arguments().repo}\" to \"{repository}\"")
                repo = Repo.clone_from(self.get_arguments().repo, repository)
                print(f" {self.APPNAME} Cloned repository successfully!")
                print(f" {self.APPNAME} Loaded repository")
            except GitCommandError as e:
                print(f" {self.APPNAME} Failed to clone repository!")
                sys.exit(1)

        if self.get_arguments().branch:
            branch = "origin/" + self.get_arguments().branch
            if branch in repo.refs:
                self.get_arguments().count += 1
                self.scanner(repo, branch, self.get_arguments().count)
                if len(self.FINDINGS) == 0:
                    print(f"\n {self.APPNAME} NO FINDINGS!")
                self.scanner_output(branch, self.FINDINGS)
            else:
                print(f" {self.APPNAME} Invalid branch!")
                sys.exit(1)
        else:
            for branch in repo.refs:
                # skip tags, HEAD and other invalid branches
                if isinstance(branch, TagReference) or str(branch) == "origin/HEAD" or not str(branch).startswith(
                        "origin"):
                    continue
                self.scanner(repo, branch, self.get_arguments().count)
                if len(self.FINDINGS) == 0:
                    print(f"\n {self.APPNAME} NO FINDINGS!")
                self.scanner_output(branch, self.FINDINGS)

        def scanner_interrupter():
            print(f"\n {self.APPNAME} Interrupted Scanning!")
            self.scanner_output(branch, self.FINDINGS, True)

        signal.signal(signal.SIGINT, scanner_interrupter())

        if sys.stdout.isatty():
            print("\n", end="")


class Commit:
    def __init__(self, sha, author, date, branch):
        self.paths = {}
        self.sha = sha
        self.date = datetime.datetime.utcfromtimestamp(date).strftime('%d/%m/%Y %H:%M:%S')
        self.author = author
        self.branch = branch

    def add_path(self, path):
        """
        Add new path
        :param path:
        :return:
        """
        self.paths[path] = Path(path)

    def get_path(self, path):
        """
        Get path
        :param path:
        :return:
        """
        if path in self.paths:
            return path
        else:
            return False

    def add_item(self, path, key_string, full_string):
        """
        Add new commit item
        :param path:
        :param key_string:
        :param full_string:
        :return:
        """
        self.paths[path].add_item(key_string, full_string)

    def get_items(self, path):
        """
        Get all commit items
        :param path:
        :return:
        """
        return self.paths[path].get_items()


class Path:
    def __init__(self, path):
        self.path = path
        self.items = {}

    def add_item(self, key_string, full_string):
        """
        Add new path item
        :param key_string:
        :param full_string:
        :return:
        """
        self.items[key_string] = full_string

    def get_items(self):
        """
        Get all path items
        :return:
        """
        return self.items.items()
