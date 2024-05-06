#!/bin/bash

sqlite3 authentication.db  < create_tables.sql

./authentication.py