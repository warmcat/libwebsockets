#!/usr/bin/env python3
#
# Push the analysis scope and rule ignores recorded in sonar-project.properties
# into the SonarCloud project settings.
#
# SonarCloud automatic analysis does not read sonar-project.properties, so
# that file is only the versioned record of what we want; this script makes
# it take effect.  See the comment at the top of sonar-project.properties.
#
#   SONAR_TOKEN=... scripts/sonar-push-settings.py [--dry-run]
#
# or with the token in scratch/.sonar_token at the top of the tree.  The
# token needs "Administer" on the project.

import sys, os, json, requests

HOST = "https://sonarcloud.io"
PROJECT = "warmcat_libwebsockets"

def parse(path):
    props = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props

def main():
    dry = "--dry-run" in sys.argv
    here = os.path.dirname(os.path.abspath(__file__))
    token = os.environ.get("SONAR_TOKEN")
    if not token:
        token = open(os.path.join(here, "..", "scratch", ".sonar_token")).read().strip()
    props = parse(os.path.join(here, "..", "sonar-project.properties"))

    excl = [e for e in props["sonar.exclusions"].split(",") if e]
    ids = props["sonar.issue.ignore.multicriteria"].split(",")
    crit = []
    for i in ids:
        crit.append({"ruleKey": props["sonar.issue.ignore.multicriteria.%s.ruleKey" % i],
                     "resourceKey": props["sonar.issue.ignore.multicriteria.%s.resourceKey" % i]})

    print("sonar.exclusions: %d patterns" % len(excl))
    print("sonar.issue.ignore.multicriteria: %d entries" % len(crit))
    if dry:
        for e in excl:
            print("  ", e)
        for c in crit:
            print("  ", c["ruleKey"], c["resourceKey"])
        return 0

    auth = (token, "")
    r = requests.post(HOST + "/api/settings/set", auth=auth,
                      data={"component": PROJECT, "key": "sonar.exclusions",
                            "values": excl})
    print("sonar.exclusions:", r.status_code, r.text[:200])
    r2 = requests.post(HOST + "/api/settings/set", auth=auth,
                       data={"component": PROJECT,
                             "key": "sonar.issue.ignore.multicriteria",
                             "fieldValues": [json.dumps(c) for c in crit]})
    print("sonar.issue.ignore.multicriteria:", r2.status_code, r2.text[:200])
    return 0 if r.ok and r2.ok else 1

if __name__ == "__main__":
    sys.exit(main())
