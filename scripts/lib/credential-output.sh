#!/bin/bash
# Shared rule for showing a freshly minted credential. Sourced by
# generate-secrets.sh, setup-microk8s.sh and deploy-dev.sh so all three answer
# the same question the same way.
#
# The rule is internal/firstboot's, applied to the shell side of the same
# problem. Those three scripts each ran `cat` on a live admin token, or echoed
# one into a "Created ..." line. That is fine on a laptop and wrong everywhere
# else: run from CI, from a wrapper that tees, or from a shell whose session is
# recorded, the token ends up permanently at rest somewhere with a far wider
# readership than the vault it opens, and it outlives its own rotation.
#
# So: the value goes to a terminal, because a terminal has a human in front of
# it and no scrollback that leaves the machine. Anywhere else, the script prints
# where the credential is and how to read it, and never what it is.

# show_credential LABEL VALUE RETRIEVAL_HINT
#
# Prints VALUE only when stdout is a terminal. Otherwise prints the hint, which
# must say where the credential can be read from.
show_credential() {
    local label="$1" value="$2" hint="$3"

    if [ -t 1 ]; then
        printf '%s:\n%s\n' "$label" "$value"
        return
    fi

    printf '%s: not shown, because stdout is not a terminal and this would put a live credential\n' "$label"
    printf 'into whatever is capturing this output. Read it with:\n  %s\n' "$hint"
}

# show_credential_file LABEL PATH
#
# The same rule for a credential that is already in a file: the file is the
# retrieval hint, so nothing has to be repeated.
show_credential_file() {
    local label="$1" path="$2"

    if [ -t 1 ]; then
        printf '%s:\n' "$label"
        cat "$path"
        printf '\n'
        return
    fi

    printf '%s: not shown, because stdout is not a terminal. It is in:\n  %s\n' "$label" "$path"
}
