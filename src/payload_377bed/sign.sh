#!/bin/bash
set -e

$@
ct_bypass -r -i ${@: -1}
