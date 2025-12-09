# Shell Scripting Tutorial
## Automating Tasks and Building DevOps Workflows

---

## Table of Contents
1. [Shell Scripting Basics](#shell-scripting-basics)
2. [Variables and Data Types](#variables-and-data-types)
3. [Control Structures](#control-structures)
4. [Functions](#functions)
5. [Text Processing](#text-processing)
6. [File Operations](#file-operations)
7. [Error Handling](#error-handling)
8. [Practical Automation Scripts](#practical-automation-scripts)
9. [Best Practices](#best-practices)

---

## Shell Scripting Basics

### What is a Shell Script?

A shell script is a text file containing a series of commands that the shell executes sequentially. It's perfect for:
- Automating repetitive tasks
- System administration
- Build processes
- Deployment automation
- Testing

### Your First Script

```bash
#!/bin/bash
# This is a comment
# The first line (shebang) tells the system which interpreter to use

echo "Hello, World!"
echo "Current directory: $(pwd)"
echo "Current user: $USER"
```

**Save and execute**:
```bash
# Create script
nano hello.sh

# Make executable
chmod +x hello.sh

# Run script
./hello.sh

# Or explicitly with bash
bash hello.sh
```

### Shebang Options

```bash
#!/bin/bash           # Bash (most common)
#!/bin/sh             # POSIX shell (portable)
#!/usr/bin/env bash   # Bash (finds in PATH, more portable)
#!/usr/bin/env python3 # Python script
#!/usr/bin/env node   # Node.js script
```

### Script Structure

```bash
#!/bin/bash

#################################
# Script: deploy.sh
# Purpose: Deploy React application
# Author: John Doe
# Date: 2024-12-06
#################################

# Exit on error
set -e

# Exit on undefined variable
set -u

# Exit on pipe failure
set -o pipefail

# Constants
readonly APP_NAME="my-react-app"
readonly DEPLOY_DIR="/var/www/html"

# Variables
BUILD_DIR="./build"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Main script logic
main() {
    echo "Starting deployment of ${APP_NAME}..."
    build_app
    deploy_app
    echo "Deployment complete!"
}

build_app() {
    echo "Building application..."
    npm run build
}

deploy_app() {
    echo "Deploying to ${DEPLOY_DIR}..."
    sudo cp -r "${BUILD_DIR}"/* "${DEPLOY_DIR}/"
}

# Run main function
main "$@"
```

---

## Variables and Data Types

### Variable Basics

```bash
#!/bin/bash

# Variable assignment (no spaces around =)
name="John"
age=30
city="New York"

# Use variables
echo "Name: $name"
echo "Name: ${name}"  # Preferred (clearer)
echo "Age: $age years old"

# Command substitution
current_dir=$(pwd)
file_count=$(ls -1 | wc -l)

echo "Current directory: $current_dir"
echo "Number of files: $file_count"

# Arithmetic
count=10
count=$((count + 1))
echo "Count: $count"

# String concatenation
first_name="John"
last_name="Doe"
full_name="${first_name} ${last_name}"
echo "Full name: $full_name"
```

### Special Variables

```bash
#!/bin/bash

echo "Script name: $0"
echo "First argument: $1"
echo "Second argument: $2"
echo "All arguments: $@"
echo "Number of arguments: $#"
echo "Exit status of last command: $?"
echo "Current process ID: $$"
echo "Last background process ID: $!"

# Usage
./script.sh arg1 arg2 arg3
```

### Environment Variables

```bash
#!/bin/bash

# Read environment variables
echo "User: $USER"
echo "Home: $HOME"
echo "Path: $PATH"
echo "Shell: $SHELL"

# Set environment variable (for child processes)
export MY_VAR="value"

# Set for current script only
LOCAL_VAR="local value"

# Load from .env file
if [ -f .env ]; then
    source .env
    # or
    . .env
fi

echo "NODE_ENV: $NODE_ENV"
echo "DATABASE_URL: $DATABASE_URL"
```

### Arrays

```bash
#!/bin/bash

# Declare array
fruits=("apple" "banana" "orange")

# Access elements
echo "${fruits[0]}"  # apple
echo "${fruits[1]}"  # banana

# All elements
echo "${fruits[@]}"

# Array length
echo "${#fruits[@]}"

# Add element
fruits+=("grape")

# Iterate over array
for fruit in "${fruits[@]}"; do
    echo "Fruit: $fruit"
done

# Associative arrays (Bash 4+)
declare -A user
user[name]="John"
user[age]=30
user[city]="New York"

echo "Name: ${user[name]}"
echo "Age: ${user[age]}"
```

---

## Control Structures

### If Statements

```bash
#!/bin/bash

# Basic if
if [ "$1" = "start" ]; then
    echo "Starting service..."
fi

# If-else
if [ -f "config.json" ]; then
    echo "Config file exists"
else
    echo "Config file not found"
    exit 1
fi

# If-elif-else
if [ "$NODE_ENV" = "production" ]; then
    echo "Running in production"
elif [ "$NODE_ENV" = "development" ]; then
    echo "Running in development"
else
    echo "Environment not set"
fi

# Multiple conditions (AND)
if [ -f "package.json" ] && [ -d "node_modules" ]; then
    echo "Node project ready"
fi

# Multiple conditions (OR)
if [ "$1" = "start" ] || [ "$1" = "restart" ]; then
    echo "Starting/restarting service"
fi

# Negation
if [ ! -f "file.txt" ]; then
    echo "File does not exist"
fi
```

### Test Operators

```bash
# File tests
[ -e file ]    # Exists
[ -f file ]    # Regular file
[ -d dir ]     # Directory
[ -r file ]    # Readable
[ -w file ]    # Writable
[ -x file ]    # Executable
[ -s file ]    # Not empty

# String comparisons
[ "$a" = "$b" ]    # Equal
[ "$a" != "$b" ]   # Not equal
[ -z "$a" ]        # Empty string
[ -n "$a" ]        # Not empty

# Numeric comparisons
[ "$a" -eq "$b" ]  # Equal
[ "$a" -ne "$b" ]  # Not equal
[ "$a" -lt "$b" ]  # Less than
[ "$a" -le "$b" ]  # Less than or equal
[ "$a" -gt "$b" ]  # Greater than
[ "$a" -ge "$b" ]  # Greater than or equal
```

### Modern Test Syntax

```bash
# [[ ]] is more powerful than [ ]
if [[ "$name" == "John" ]]; then
    echo "Hello John"
fi

# Pattern matching
if [[ "$file" == *.txt ]]; then
    echo "Text file"
fi

# Regular expressions
if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "Valid email"
fi
```

### Case Statements

```bash
#!/bin/bash

case "$1" in
    start)
        echo "Starting service..."
        systemctl start myapp
        ;;
    stop)
        echo "Stopping service..."
        systemctl stop myapp
        ;;
    restart)
        echo "Restarting service..."
        systemctl restart myapp
        ;;
    status)
        systemctl status myapp
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
```

### Loops

**For Loop**:
```bash
#!/bin/bash

# Iterate over list
for item in apple banana orange; do
    echo "Fruit: $item"
done

# Iterate over files
for file in *.txt; do
    echo "Processing: $file"
    cat "$file"
done

# C-style for loop
for ((i=1; i<=10; i++)); do
    echo "Number: $i"
done

# Iterate over command output
for user in $(cat /etc/passwd | cut -d: -f1); do
    echo "User: $user"
done

# Range
for i in {1..10}; do
    echo "Count: $i"
done

# Step
for i in {0..100..10}; do
    echo "Multiple of 10: $i"
done
```

**While Loop**:
```bash
#!/bin/bash

# Basic while loop
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done

# Read file line by line
while IFS= read -r line; do
    echo "Line: $line"
done < input.txt

# Infinite loop
while true; do
    echo "Running..."
    sleep 5
done

# Loop until service is up
while ! curl -f http://localhost:3000 >/dev/null 2>&1; do
    echo "Waiting for service..."
    sleep 2
done
echo "Service is up!"
```

**Until Loop**:
```bash
#!/bin/bash

count=1
until [ $count -gt 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

---

## Functions

### Basic Functions

```bash
#!/bin/bash

# Function definition
greet() {
    echo "Hello, $1!"
}

# Call function
greet "John"
greet "Alice"

# Function with return value
add() {
    local result=$(( $1 + $2 ))
    echo "$result"
}

sum=$(add 5 3)
echo "Sum: $sum"

# Function with return code
check_service() {
    if systemctl is-active --quiet "$1"; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

if check_service nginx; then
    echo "Nginx is running"
else
    echo "Nginx is not running"
fi
```

### Advanced Functions

```bash
#!/bin/bash

# Function with local variables
calculate() {
    local num1=$1
    local num2=$2
    local operation=$3

    case "$operation" in
        add)
            echo $(( num1 + num2 ))
            ;;
        subtract)
            echo $(( num1 - num2 ))
            ;;
        multiply)
            echo $(( num1 * num2 ))
            ;;
        divide)
            echo $(( num1 / num2 ))
            ;;
        *)
            echo "Invalid operation"
            return 1
            ;;
    esac
}

result=$(calculate 10 5 add)
echo "10 + 5 = $result"

# Function with default parameters
deploy() {
    local env=${1:-production}
    local branch=${2:-main}

    echo "Deploying from $branch to $env"
}

deploy                    # Uses defaults
deploy staging develop    # Uses specified values
```

---

## Text Processing

### grep, sed, awk

```bash
#!/bin/bash

# grep - Search for patterns
grep "error" app.log
grep -i "warning" app.log        # Case-insensitive
grep -r "TODO" src/              # Recursive
grep -v "debug" app.log          # Invert match
grep -c "error" app.log          # Count matches
grep -n "error" app.log          # Show line numbers

# sed - Stream editor
sed 's/old/new/' file.txt        # Replace first occurrence
sed 's/old/new/g' file.txt       # Replace all occurrences
sed -i 's/old/new/g' file.txt    # In-place edit
sed -n '10,20p' file.txt         # Print lines 10-20
sed '5d' file.txt                # Delete line 5
sed '/pattern/d' file.txt        # Delete lines matching pattern

# awk - Text processing
awk '{print $1}' file.txt        # Print first column
awk '{print $1, $3}' file.txt    # Print columns 1 and 3
awk -F: '{print $1}' /etc/passwd # Use : as delimiter
awk '$3 > 100' data.txt          # Filter rows where col 3 > 100
awk '{sum += $1} END {print sum}' numbers.txt  # Sum first column
```

### Practical Examples

```bash
#!/bin/bash

# Extract emails from file
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' contacts.txt

# Find large files
find . -type f -size +100M -exec ls -lh {} \; | awk '{print $9, $5}'

# Parse JSON (with jq)
cat data.json | jq '.users[] | .name'

# Process CSV
awk -F, '{print $1, $3}' data.csv

# Count occurrences
cat app.log | grep "ERROR" | wc -l

# Get unique values
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Replace in multiple files
find . -name "*.js" -exec sed -i 's/var /let /g' {} \;
```

---

## File Operations

### Reading Files

```bash
#!/bin/bash

# Read entire file
content=$(cat file.txt)

# Read line by line
while IFS= read -r line; do
    echo "Line: $line"
done < file.txt

# Read with line numbers
while IFS= read -r line; do
    echo "$line_num: $line"
    line_num=$((line_num + 1))
done < file.txt

# Read CSV
while IFS=, read -r col1 col2 col3; do
    echo "Name: $col1, Age: $col2, City: $col3"
done < data.csv
```

### Writing Files

```bash
#!/bin/bash

# Overwrite file
echo "Hello World" > file.txt

# Append to file
echo "New line" >> file.txt

# Write multiple lines
cat > config.txt <<EOF
server {
    listen 80;
    server_name example.com;
}
EOF

# Write with heredoc
cat <<EOF > script.sh
#!/bin/bash
echo "Generated script"
EOF
chmod +x script.sh
```

### File Manipulation

```bash
#!/bin/bash

# Copy with backup
cp file.txt file.txt.bak
cp -r src/ src_backup/

# Move/rename
mv old_name.txt new_name.txt

# Delete safely
rm -i file.txt         # Interactive
rm -f file.txt         # Force
rm -rf directory/      # Recursive force (dangerous!)

# Find and delete
find . -name "*.tmp" -delete
find . -type f -mtime +30 -delete  # Files older than 30 days

# Archive and compress
tar -czf backup.tar.gz /var/www/
tar -xzf backup.tar.gz

# Create directory structure
mkdir -p /path/to/nested/directory
```

---

## Error Handling

### Exit Codes

```bash
#!/bin/bash

# Check exit code
npm install
if [ $? -eq 0 ]; then
    echo "Installation successful"
else
    echo "Installation failed"
    exit 1
fi

# Shorter version
if npm install; then
    echo "Success"
else
    echo "Failed"
    exit 1
fi
```

### Set Options

```bash
#!/bin/bash

# Exit on error
set -e

# Exit on undefined variable
set -u

# Exit on pipe failure
set -o pipefail

# All together
set -euo pipefail

# Disable for specific command
set +e
command_that_might_fail
set -e
```

### Error Messages

```bash
#!/bin/bash

# Print to stderr
echo "Error: File not found" >&2

# Function for errors
error() {
    echo "[ERROR] $*" >&2
    exit 1
}

info() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

# Usage
if [ ! -f "config.json" ]; then
    error "Config file not found"
fi

info "Starting deployment..."
```

### Trap Signals

```bash
#!/bin/bash

# Cleanup on exit
cleanup() {
    echo "Cleaning up..."
    rm -f /tmp/myapp.lock
    kill $background_pid 2>/dev/null
}

trap cleanup EXIT

# Catch Ctrl+C
trap 'echo "Interrupted"; exit 1' INT TERM

# Main script
echo "Running..."
touch /tmp/myapp.lock
sleep 100 &
background_pid=$!
wait
```

---

## Practical Automation Scripts

### Script 1: React Build and Deploy

```bash
#!/bin/bash

#####################################
# React Application Deployment Script
#####################################

set -euo pipefail

# Configuration
readonly APP_NAME="my-react-app"
readonly BUILD_DIR="./build"
readonly DEPLOY_DIR="/var/www/html"
readonly BACKUP_DIR="/var/backups/webapp"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f /tmp/deploy.lock
}

trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [ ! -f "package.json" ]; then
        log_error "package.json not found. Are you in the right directory?"
        exit 1
    fi

    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed"
        exit 1
    fi

    if [ -f /tmp/deploy.lock ]; then
        log_error "Another deployment is in progress"
        exit 1
    fi

    touch /tmp/deploy.lock
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    npm ci || npm install
}

# Run tests
run_tests() {
    log_info "Running tests..."

    if ! npm test -- --watchAll=false; then
        log_error "Tests failed"
        return 1
    fi

    log_info "All tests passed"
}

# Build application
build_app() {
    log_info "Building application..."

    # Clean previous build
    rm -rf "$BUILD_DIR"

    # Build
    if ! npm run build; then
        log_error "Build failed"
        exit 1
    fi

    log_info "Build completed successfully"
}

# Create backup
create_backup() {
    log_info "Creating backup..."

    if [ -d "$DEPLOY_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        tar -czf "${BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz" -C "$DEPLOY_DIR" .
        log_info "Backup created: ${BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz"

        # Keep only last 5 backups
        ls -t "${BACKUP_DIR}"/backup_*.tar.gz | tail -n +6 | xargs -r rm
    fi
}

# Deploy application
deploy_app() {
    log_info "Deploying application..."

    sudo mkdir -p "$DEPLOY_DIR"
    sudo cp -r "${BUILD_DIR}"/* "$DEPLOY_DIR/"
    sudo chown -R www-data:www-data "$DEPLOY_DIR"

    log_info "Application deployed to $DEPLOY_DIR"
}

# Restart web server
restart_server() {
    log_info "Restarting Nginx..."

    if ! sudo nginx -t; then
        log_error "Nginx configuration test failed"
        return 1
    fi

    sudo systemctl reload nginx
    log_info "Nginx reloaded"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."

    local url="http://localhost"

    if curl -sf "$url" > /dev/null; then
        log_info "Deployment verification successful"
    else
        log_error "Deployment verification failed"
        return 1
    fi
}

# Rollback
rollback() {
    log_error "Deployment failed. Rolling back..."

    local latest_backup=$(ls -t "${BACKUP_DIR}"/backup_*.tar.gz | head -n 1)

    if [ -n "$latest_backup" ]; then
        sudo rm -rf "${DEPLOY_DIR}"/*
        sudo tar -xzf "$latest_backup" -C "$DEPLOY_DIR"
        sudo systemctl reload nginx
        log_info "Rollback completed"
    else
        log_error "No backup found for rollback"
    fi
}

# Main deployment function
main() {
    log_info "Starting deployment of $APP_NAME"

    check_prerequisites
    install_dependencies

    # Run tests (optional, can be skipped with flag)
    if [ "${SKIP_TESTS:-0}" != "1" ]; then
        run_tests || { log_warn "Tests failed, but continuing..."; }
    fi

    build_app
    create_backup
    deploy_app

    if ! restart_server || ! verify_deployment; then
        rollback
        exit 1
    fi

    log_info "Deployment completed successfully!"
}

# Run main function
main "$@"
```

**Usage**:
```bash
# Normal deployment
./deploy.sh

# Skip tests
SKIP_TESTS=1 ./deploy.sh
```

### Script 2: System Backup

```bash
#!/bin/bash

#####################################
# System Backup Script
#####################################

set -euo pipefail

# Configuration
readonly BACKUP_SOURCE="/home /etc /var/www"
readonly BACKUP_DEST="/backups"
readonly RETENTION_DAYS=7
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly BACKUP_FILE="${BACKUP_DEST}/backup_${TIMESTAMP}.tar.gz"
readonly LOG_FILE="/var/log/backup.log"

# Logging
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Create backup directory
mkdir -p "$BACKUP_DEST"

log "Starting backup..."

# Create backup
if tar -czf "$BACKUP_FILE" $BACKUP_SOURCE 2>>"$LOG_FILE"; then
    log "Backup created: $BACKUP_FILE"

    # Calculate size
    size=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Backup size: $size"
else
    log "ERROR: Backup failed"
    exit 1
fi

# Remove old backups
log "Removing backups older than $RETENTION_DAYS days..."
find "$BACKUP_DEST" -name "backup_*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete

# List current backups
log "Current backups:"
ls -lh "$BACKUP_DEST"/backup_*.tar.gz | tee -a "$LOG_FILE"

log "Backup completed successfully"
```

**Cron job**:
```bash
# Run daily at 2 AM
0 2 * * * /usr/local/bin/backup.sh
```

### Script 3: Git Automation

```bash
#!/bin/bash

#####################################
# Git Automation Script
#####################################

set -euo pipefail

# Configuration
readonly BRANCH=$(git rev-parse --abbrev-ref HEAD)
readonly COMMIT_MSG="${1:-Auto-commit: $(date +'%Y-%m-%d %H:%M:%S')}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not a git repository"
    exit 1
fi

# Check for uncommitted changes
if git diff-index --quiet HEAD --; then
    echo "No changes to commit"
    exit 0
fi

# Show status
echo "Git status:"
git status --short

# Confirmation
read -p "Commit and push these changes? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 0
fi

# Add all changes
git add .

# Commit
git commit -m "$COMMIT_MSG"

# Push
if git push origin "$BRANCH"; then
    echo "Successfully pushed to $BRANCH"
else
    echo "Error: Push failed"
    exit 1
fi
```

### Script 4: Log Monitor

```bash
#!/bin/bash

#####################################
# Log Monitor Script
#####################################

set -euo pipefail

# Configuration
readonly LOG_FILE="/var/log/nginx/error.log"
readonly ALERT_EMAIL="admin@example.com"
readonly ERROR_THRESHOLD=10

# Count errors in last 5 minutes
error_count=$(grep "$(date -d '5 minutes ago' +'%d/%b/%Y:%H:%M')" "$LOG_FILE" | grep -c "\[error\]" || true)

echo "Errors in last 5 minutes: $error_count"

if [ "$error_count" -gt "$ERROR_THRESHOLD" ]; then
    echo "Alert: High error rate detected!"

    # Send email (requires mailutils)
    if command -v mail &> /dev/null; then
        echo "Error threshold exceeded: $error_count errors" | \
            mail -s "Server Alert: High Error Rate" "$ALERT_EMAIL"
    fi

    # Send Slack notification (example)
    if [ -n "${SLACK_WEBHOOK:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"Alert: $error_count errors in last 5 minutes\"}" \
            "$SLACK_WEBHOOK"
    fi
fi
```

### Script 5: Development Environment Setup

```bash
#!/bin/bash

#####################################
# Development Environment Setup
#####################################

set -euo pipefail

echo "Setting up development environment..."

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install basic tools
echo "Installing basic tools..."
sudo apt install -y curl git build-essential vim htop

# Install Node.js via nvm
if [ ! -d "$HOME/.nvm" ]; then
    echo "Installing nvm..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

    echo "Installing Node.js..."
    nvm install 20
    nvm use 20
    nvm alias default 20
else
    echo "nvm already installed"
fi

# Install global npm packages
echo "Installing global npm packages..."
npm install -g typescript ts-node nodemon pm2

# Install Docker
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker "$USER"
    rm get-docker.sh
else
    echo "Docker already installed"
fi

# Configure git
echo "Configuring git..."
read -p "Enter your name: " git_name
read -p "Enter your email: " git_email

git config --global user.name "$git_name"
git config --global user.email "$git_email"
git config --global init.defaultBranch main

# Create project structure
echo "Creating project structure..."
mkdir -p ~/projects/{personal,work,learning}

echo "Development environment setup complete!"
echo "Please log out and log back in for Docker group changes to take effect."
```

---

## Best Practices

### 1. Always Use Shebang

```bash
#!/bin/bash
# Not just "bash" or "sh"
```

### 2. Use Strict Mode

```bash
set -euo pipefail
# e: Exit on error
# u: Exit on undefined variable
# pipefail: Exit on pipe failure
```

### 3. Quote Variables

```bash
# Good
echo "$variable"
rm "$file_name"

# Bad (can break with spaces)
echo $variable
rm $file_name
```

### 4. Use Meaningful Names

```bash
# Good
user_count=10
database_host="localhost"

# Bad
x=10
h="localhost"
```

### 5. Check Command Existence

```bash
if ! command -v node &> /dev/null; then
    echo "Node.js is not installed"
    exit 1
fi
```

### 6. Validate Input

```bash
if [ $# -ne 2 ]; then
    echo "Usage: $0 <source> <destination>"
    exit 1
fi
```

### 7. Use Functions

```bash
# Break complex scripts into functions
deploy() {
    build_app
    run_tests
    copy_files
    restart_server
}
```

### 8. Document Your Scripts

```bash
#!/bin/bash
#####################################
# Script: deploy.sh
# Purpose: Deploy React application
# Usage: ./deploy.sh [environment]
# Author: John Doe
# Date: 2024-12-06
#####################################
```

### 9. Handle Cleanup

```bash
cleanup() {
    rm -f /tmp/myapp.lock
}
trap cleanup EXIT
```

### 10. Use ShellCheck

```bash
# Install
sudo apt install shellcheck

# Check script
shellcheck script.sh
```

---

## Key Takeaways

1. **Start with shebang** - Specify interpreter
2. **Use strict mode** - Catch errors early
3. **Quote variables** - Avoid word splitting
4. **Functions are your friend** - Organize complex scripts
5. **Error handling** - Always check exit codes
6. **Test your scripts** - Use ShellCheck
7. **Document** - Future you will thank you
8. **Security** - Never trust user input
9. **Portability** - Use POSIX when possible
10. **Automation** - If you do it twice, script it

---

## Next Steps

- Practice writing scripts for daily tasks
- Learn advanced text processing with awk
- Explore process management and signals
- Study systemd service creation
- Learn about CI/CD pipeline scripting
- Master Git hooks for automation
- Build deployment automation
- Create monitoring and alerting scripts

**For React/TypeScript Developers**: Shell scripting is essential for build processes, deployment automation, and DevOps workflows. Master it to streamline your development workflow!
