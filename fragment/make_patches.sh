#!/usr/bin/env bash

function make_patch_for() {
    local name=$1

    if [ ! -f "${name}_fragment.rego" ]; then
        echo "Fragment file ${name}_fragment.rego not found"
        exit 1
    fi
    if [ ! -f "${name}_fragment.orig.rego" ]; then
        echo "Original fragment file ${name}_fragment.orig.rego not found"
        exit 1
    fi
    diff -u "${name}_fragment.orig.rego" "${name}_fragment.rego" > "${name}_fragment.rego.patch"
    status=$?
    if [ $status -ne 0 ] && [ $status -ne 1 ]; then
        echo "Error generating patch for ${name}"
        exit 1
    fi
    if [ $status -eq 0 ]; then
        echo "No changes for ${name}?"
    else
        echo "${name}_fragment.rego.patch created."
    fi
}

make_patch_for "skr"
make_patch_for "encfs"
