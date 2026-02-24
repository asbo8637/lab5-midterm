#!/usr/bin/env python3
import os
from git import Repo

# files from previous objectives
files = ["report.txt", "cpu_usage.jpg"]

def add_files(r):
    count = 0
    for fname in files:
        if os.path.exists(fname):
            r.index.add([fname])
            print(f"added {fname}")
            count = count + 1
    
    if count > 0:
        msg = "Add report and cpu graph"
        r.index.commit(msg)
        print("committed")

def check_modified(r):
    print("checking for changes...")
    
    diffs = r.index.diff(None)
    modified_files = []
    for d in diffs:
        modified_files.append(d.a_path)
    
    untracked = r.untracked_files
    
    to_add = modified_files + untracked
    
    if len(to_add) == 0:
        print("nothing changed")
        return
    
    print(f"changes: {to_add}")
    
    # stage everything
    for file in to_add:
        r.index.add([file])
    
    r.index.commit("modified files update")

def main():
    current_repo = Repo(".")
    remote = current_repo.remote("origin")
    
    print("repository:", remote.url)
    
    # push the generated files
    add_files(current_repo)
    
    # check for modified stuff
    check_modified(current_repo)
    
    # push everything
    print("pushing...")
    remote.push()
    print("done!")

if __name__ == "__main__":
    raise SystemExit(main())
