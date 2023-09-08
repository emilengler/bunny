#!/usr/bin/env sh
#
# Launches an interactive iex shell with an increased stack size, which is
# required for the SKEM key generation.

iex --erl "+sssdcpu 1024" -S mix