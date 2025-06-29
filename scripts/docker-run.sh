#!/bin/bash

# Gerion CLI Docker Runner Script
# This script provides convenient ways to run Gerion CLI with Docker

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="gerion-cli"
CODE_PATH="."
OUTPUT_DIR="./output"
SCAN_TYPE="secrets"
FORMAT="json"
LOG_LEVEL="info"

# Function to print usage
usage() {
    echo -e "${BLUE}Gerion CLI Docker Runner${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE        Scan type: secrets or sca (default: secrets)"
    echo "  -p, --path PATH        Code path to scan (default: current directory)"
    echo "  -o, --output FILE      Output file (disables API sending)"
    echo "  -f, --format FORMAT    Output format: json, markdown, sarif (default: json)"
    echo "  -l, --log-level LEVEL  Log level: debug, info, warning, error, critical (default: info)"
    echo "  -b, --build           Build the Docker image before running"
    echo "  -i, --interactive     Run with interactive terminal (-it flag)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  GERION_API_URL         API URL for sending results"
    echo "  GERION_CLIENT_ID       Client ID for API authentication"
    echo "  GERION_CLIENT_SECRET   Client secret for API authentication"
    echo ""
    echo "Examples:"
    echo "  $0 --type secrets --path ./src"
    echo "  $0 --type sca --output results.json --format json"
    echo "  $0 --type secrets --log-level debug --interactive"
}

# Function to check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
        exit 1
    fi
}

# Function to build Docker image
build_image() {
    echo -e "${BLUE}Building Docker image...${NC}"
    docker build -t $IMAGE_NAME .
    echo -e "${GREEN}Docker image built successfully${NC}"
}

# Function to run scan
run_scan() {
    local scan_cmd="$1"
    local docker_args="$2"
    
    echo -e "${BLUE}Running $scan_cmd scan...${NC}"
    echo -e "${YELLOW}Code path: $CODE_PATH${NC}"
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo -e "${YELLOW}Output file: $OUTPUT_FILE${NC}"
        echo -e "${YELLOW}Format: $FORMAT${NC}"
    else
        echo -e "${YELLOW}API integration: ${GERION_API_URL:+enabled}${GERION_API_URL:-disabled}${NC}"
    fi
    
    # Create output directory if needed
    if [ -n "$OUTPUT_FILE" ]; then
        mkdir -p "$(dirname "$OUTPUT_FILE")"
    fi
    
    # Determine the Git repository root for better metadata detection
    local git_root=""
    if command -v git &> /dev/null; then
        # Try to find Git root from the code path
        if [ -d "$CODE_PATH/.git" ]; then
            git_root="$CODE_PATH"
        else
            # Try to find Git root from current directory
            git_root=$(git -C "$CODE_PATH" rev-parse --show-toplevel 2>/dev/null || echo "")
        fi
    fi
    
    # Use Git root if found, otherwise use the original code path
    local mount_path="$CODE_PATH"
    local work_dir="/code"
    
    if [ -n "$git_root" ]; then
        mount_path="$git_root"
        # Calculate relative path from Git root to code path
        if [ "$git_root" != "$CODE_PATH" ]; then
            work_dir="/code/$(realpath --relative-to="$git_root" "$CODE_PATH")"
        fi
        echo -e "${YELLOW}Git repository detected: $git_root${NC}"
        echo -e "${YELLOW}Working directory: $work_dir${NC}"
    else
        echo -e "${YELLOW}No Git repository detected, using code path directly${NC}"
    fi
    
    # Build Docker command
    local docker_cmd="docker run --rm"
    
    # Add interactive flag if requested
    if [ "$INTERACTIVE" = true ]; then
        docker_cmd="$docker_cmd -it"
    fi
    
    # Add volume mounts
    docker_cmd="$docker_cmd -v \"$(realpath "$mount_path"):/code\""
    if [ -n "$OUTPUT_FILE" ]; then
        docker_cmd="$docker_cmd -v \"$(realpath "$(dirname "$OUTPUT_FILE")"):/output\""
    fi
    
    # Add environment variables for better terminal support
    docker_cmd="$docker_cmd -e TERM=xterm-256color"
    docker_cmd="$docker_cmd -e PYTHONUNBUFFERED=1"
    docker_cmd="$docker_cmd -e FORCE_COLOR=1"
    
    # Add API environment variables
    if [ -n "$GERION_API_URL" ]; then
        docker_cmd="$docker_cmd -e GERION_API_URL=\"$GERION_API_URL\""
    fi
    if [ -n "$GERION_CLIENT_ID" ]; then
        docker_cmd="$docker_cmd -e GERION_CLIENT_ID=\"$GERION_CLIENT_ID\""
    fi
    if [ -n "$GERION_CLIENT_SECRET" ]; then
        docker_cmd="$docker_cmd -e GERION_CLIENT_SECRET=\"$GERION_CLIENT_SECRET\""
    fi
    
    # Add CI/CD environment variables if available
    for var in GITHUB_REPOSITORY GITHUB_REF_NAME GITHUB_SHA GITHUB_RUN_ID \
                CI_PROJECT_NAME CI_COMMIT_REF_NAME CI_COMMIT_SHA CI_PIPELINE_ID \
                GIT_URL GIT_BRANCH GIT_COMMIT BUILD_NUMBER; do
        if [ -n "${!var}" ]; then
            docker_cmd="$docker_cmd -e $var=\"${!var}\""
        fi
    done
    
    # Add Git metadata if available and not in CI/CD
    if [ -z "$GITHUB_REPOSITORY" ] && [ -z "$CI_PROJECT_NAME" ] && [ -z "$GIT_URL" ]; then
        if command -v git &> /dev/null; then
            # Get repository name from Git
            if [ -n "$git_root" ]; then
                # Get the actual repository name, not just the basename
                repo_name=$(basename "$git_root")
                # If the basename is ".", try to get the real name from git remote
                if [ "$repo_name" = "." ]; then
                    repo_name=$(git -C "$git_root" remote get-url origin 2>/dev/null | sed 's/.*\///' | sed 's/\.git$//' || basename "$git_root")
                fi
                docker_cmd="$docker_cmd -e GERION_REPO_NAME=\"$repo_name\""
            fi
            
            # Get current branch
            current_branch=$(git -C "$CODE_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
            if [ -n "$current_branch" ]; then
                docker_cmd="$docker_cmd -e GERION_BRANCH_NAME=\"$current_branch\""
            fi
            
            # Get current commit
            current_commit=$(git -C "$CODE_PATH" rev-parse HEAD 2>/dev/null || echo "")
            if [ -n "$current_commit" ]; then
                docker_cmd="$docker_cmd -e GERION_COMMIT_HASH=\"$current_commit\""
            fi
        fi
    fi
    
    # Add working directory if different from /code
    if [ "$work_dir" != "/code" ]; then
        docker_cmd="$docker_cmd -w $work_dir"
    fi
    
    # Add image and command
    docker_cmd="$docker_cmd $IMAGE_NAME $scan_cmd"
    
    # Add arguments
    if [ -n "$OUTPUT_FILE" ]; then
        # Convert output file path to container path
        local container_output="/output/$(basename "$OUTPUT_FILE")"
        docker_cmd="$docker_cmd --output-file $container_output --format $FORMAT"
    fi
    
    docker_cmd="$docker_cmd --log-level $LOG_LEVEL /code"
    
    echo -e "${BLUE}Executing: $docker_cmd${NC}"
    echo ""
    
    # Execute the command
    eval $docker_cmd
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            SCAN_TYPE="$2"
            shift 2
            ;;
        -p|--path)
            CODE_PATH="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -b|--build)
            BUILD_IMAGE=true
            shift
            ;;
        -i|--interactive)
            INTERACTIVE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Validate scan type
if [[ "$SCAN_TYPE" != "secrets" && "$SCAN_TYPE" != "sca" ]]; then
    echo -e "${RED}Error: Invalid scan type. Use 'secrets' or 'sca'${NC}"
    exit 1
fi

# Validate format
if [[ "$FORMAT" != "json" && "$FORMAT" != "markdown" && "$FORMAT" != "sarif" ]]; then
    echo -e "${RED}Error: Invalid format. Use 'json', 'markdown', or 'sarif'${NC}"
    exit 1
fi

# Validate log level
if [[ "$LOG_LEVEL" != "debug" && "$LOG_LEVEL" != "info" && "$LOG_LEVEL" != "warning" && "$LOG_LEVEL" != "error" && "$LOG_LEVEL" != "critical" ]]; then
    echo -e "${RED}Error: Invalid log level. Use 'debug', 'info', 'warning', 'error', or 'critical'${NC}"
    exit 1
fi

# Check if code path exists
if [ ! -d "$CODE_PATH" ]; then
    echo -e "${RED}Error: Code path '$CODE_PATH' does not exist${NC}"
    exit 1
fi

# Check Docker
check_docker

# Build image if requested
if [ "$BUILD_IMAGE" = true ]; then
    build_image
fi

# Check if image exists
if ! docker image inspect $IMAGE_NAME &> /dev/null; then
    echo -e "${YELLOW}Docker image not found. Building...${NC}"
    build_image
fi

# Run the scan
if [ "$SCAN_TYPE" = "secrets" ]; then
    run_scan "secrets-scan"
else
    run_scan "sca-scan"
fi

echo -e "${GREEN}Scan completed successfully!${NC}" 