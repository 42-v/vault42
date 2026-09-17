package spec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every dependency override either binds something, or says why it does not.
//
// package.json's pnpm.overrides block is a security control: it forces a
// resolved version for a package somewhere in the tree, usually to move off an
// advisory. Eleven of the twelve entries do exactly that. One -- lodash -- names
// a package that is not in pnpm-lock.yaml at all, and there is no way to tell
// from the file whether that is a pre-emptive pin somebody meant, or a control
// left behind after the dependency that needed it went away.
//
// Both readings lead somewhere bad. Read as dead, it gets deleted and a
// forward-looking control goes with it. Read as live, it sits there implying a
// protection nobody is getting, because an override for an absent package binds
// nothing.
//
// JSON carries no comments, so the reason lives here, and it is checked in both
// directions: an override that binds nothing must be listed, and a listing that
// no longer matches an override must be removed. That is what stops this from
// becoming the thing it documents.
//
// What this does NOT check is whether a range is still satisfiable by something
// published -- that needs the registry, and a gate that reaches the network
// fails on an airplane rather than on a defect. Checked by hand at the time of
// writing: all twelve resolve, including the three that deliberately pin below
// the current major (nanoid <4, js-yaml <5, fast-uri <4).

// preEmptiveOverrides are the overrides that bind nothing today, with the reason
// each is kept anyway.
var preEmptiveOverrides = map[string]string{
	"lodash": "nothing in the tree depends on lodash, and the pin is kept so that anything " +
		"which starts to cannot arrive on the 4.17 line. It is inert until then: pnpm applies " +
		"an override only to a package it actually resolves.",
}

// lockedPackage matches the name in a pnpm-lock.yaml package key, which is
// `  name@version:` or `  '@scope/name@version':` for scoped packages.
var lockedPackage = regexp.MustCompile(`(?m)^  '?(@?[^@'\s][^@']*)@[^:]*'?:`)

func TestEveryDependencyOverrideBindsSomethingOrSaysWhyNot(t *testing.T) {
	root := repoRoot(t)

	var pkg struct {
		Pnpm struct {
			Overrides map[string]string `json:"overrides"`
		} `json:"pnpm"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if len(pkg.Pnpm.Overrides) == 0 {
		t.Fatal("package.json declares no pnpm.overrides. If the block was removed this gate " +
			"can go, but it must not be left matching an empty map: it would then pass while " +
			"checking nothing.")
	}

	lock := readFileString(t, filepath.Join(root, "pnpm-lock.yaml"))
	resolved := map[string]bool{}
	for _, m := range lockedPackage.FindAllStringSubmatch(lock, -1) {
		resolved[m[1]] = true
	}
	if len(resolved) == 0 {
		t.Fatal("no package names parsed out of pnpm-lock.yaml, so every override below would " +
			"read as unbound. The lockfile format changed; fix the pattern rather than the " +
			"expectations.")
	}

	names := make([]string, 0, len(pkg.Pnpm.Overrides))
	for name := range pkg.Pnpm.Overrides {
		names = append(names, name)
	}
	sort.Strings(names)

	unbound := map[string]bool{}
	for _, name := range names {
		// `eslint>ajv` overrides ajv only where eslint asks for it; the package
		// that has to exist is the one on the right.
		target := name
		if i := strings.LastIndex(name, ">"); i >= 0 {
			target = name[i+1:]
		}
		if resolved[target] {
			continue
		}
		unbound[target] = true
		if _, documented := preEmptiveOverrides[target]; !documented {
			t.Errorf("pnpm.overrides pins %q to %q and no package named %q is resolved in "+
				"pnpm-lock.yaml, so the override binds nothing.\n"+
				"Either it is dead and should be removed, or it is a pre-emptive pin and "+
				"belongs in preEmptiveOverrides with the reason -- an override that protects "+
				"nothing while looking like it protects something is the worse of the two.",
				name, pkg.Pnpm.Overrides[name], target)
		}
	}

	for target, why := range preEmptiveOverrides {
		if _, still := pkg.Pnpm.Overrides[target]; !still {
			t.Errorf("preEmptiveOverrides explains %q (%s) and package.json no longer overrides "+
				"it. Remove the entry: a reason for a control that is gone reads as though the "+
				"control is still there.", target, why)
			continue
		}
		if !unbound[target] {
			t.Errorf("preEmptiveOverrides calls %q pre-emptive, but pnpm-lock.yaml now resolves "+
				"it, so the override binds a real package. Remove the entry -- it is describing "+
				"the tree as it was.", target)
		}
	}
}
