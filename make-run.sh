#!/bin/bash

cargo build --release --verbose
sudo chown root target/release/chucker
sudo chmod u+s target/release/chucker
target/release/chucker
