#!/bin/bash

# Gerion CLI Docker Test Script
# This script helps test the Docker build and functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="gerion-cli-test"
TEST_DIR="./test-docker"

# Function to print usage
usage() {
    echo -e "${BLUE}Gerion CLI Docker Test Script${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --image NAME       Docker image name (default: gerion-cli-test)"
    echo "  -t, --test-dir DIR     Test directory (default: ./test-docker)"
    echo "  -c, --clean           Clean up test artifacts"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Run full test suite"
    echo "  $0 --clean            # Clean up test artifacts"
    echo "  $0 --image my-test    # Use custom image name"
}

# Function to check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
        exit 1
    fi
}

# Function to clean up test artifacts
cleanup() {
    echo -e "${BLUE}Cleaning up test artifacts...${NC}"
    
    # Remove test directory
    if [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
        echo -e "${GREEN}Removed test directory: $TEST_DIR${NC}"
    fi
    
    # Remove test image
    if docker image inspect $IMAGE_NAME &> /dev/null; then
        docker rmi $IMAGE_NAME
        echo -e "${GREEN}Removed test image: $IMAGE_NAME${NC}"
    fi
    
    # Remove any test containers
    docker ps -a --filter "ancestor=$IMAGE_NAME" --format "{{.ID}}" | xargs -r docker rm -f
    echo -e "${GREEN}Cleaned up test containers${NC}"
}

# Function to create test files
create_test_files() {
    echo -e "${BLUE}Creating test files...${NC}"
    
    mkdir -p "$TEST_DIR"
    
    # Create a simple Python file with a potential secret
    cat > "$TEST_DIR/test_secret.py" << 'EOF'
# Test file with potential secrets
API_KEY = "sk-1234567890abcdef1234567890abcdef12345678"
PASSWORD = "super_secret_password_123"
DATABASE_URL = "postgresql://user:password@localhost:5432/db"

# Normal variable
NORMAL_VAR = "this_is_normal"
EOF

    # Create a requirements.txt file for SCA testing
    cat > "$TEST_DIR/requirements.txt" << 'EOF'
requests==2.25.1
urllib3==1.26.4
EOF

    # Create a .gitignore to make it look like a real project
    cat > "$TEST_DIR/.gitignore" << 'EOF'
__pycache__/
*.pyc
.env
EOF

    echo -e "${GREEN}Test files created in: $TEST_DIR${NC}"
}

# Function to test Docker build
test_build() {
    echo -e "${BLUE}Testing Docker build...${NC}"
    
    # Build the image
    docker build -t $IMAGE_NAME .
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Docker build successful!${NC}"
    else
        echo -e "${RED}Docker build failed!${NC}"
        exit 1
    fi
}

# Function to test secrets scan
test_secrets_scan() {
    echo -e "${BLUE}Testing secrets scan...${NC}"
    
    # Run secrets scan
    docker run --rm \
        -v "$(realpath "$TEST_DIR"):/code" \
        $IMAGE_NAME secrets-scan /code
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Secrets scan test passed!${NC}"
    else
        echo -e "${RED}Secrets scan test failed!${NC}"
        return 1
    fi
}

# Function to test SCA scan
test_sca_scan() {
    echo -e "${BLUE}Testing SCA scan...${NC}"
    
    # Run SCA scan
    docker run --rm \
        -v "$(realpath "$TEST_DIR"):/code" \
        $IMAGE_NAME sca-scan /code
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SCA scan test passed!${NC}"
    else
        echo -e "${RED}SCA scan test failed!${NC}"
        return 1
    fi
}

# Function to test file output
test_file_output() {
    echo -e "${BLUE}Testing file output...${NC}"
    
    # Create output directory
    mkdir -p "$TEST_DIR/output"
    
    # Test JSON output
    docker run --rm \
        -v "$(realpath "$TEST_DIR"):/code" \
        -v "$(realpath "$TEST_DIR/output"):/output" \
        $IMAGE_NAME secrets-scan /code --output-file /output/test_results.json --format json
    
    if [ -f "$TEST_DIR/output/test_results.json" ]; then
        echo -e "${GREEN}JSON output test passed!${NC}"
    else
        echo -e "${RED}JSON output test failed!${NC}"
        return 1
    fi
    
    # Test Markdown output
    docker run --rm \
        -v "$(realpath "$TEST_DIR"):/code" \
        -v "$(realpath "$TEST_DIR/output"):/output" \
        $IMAGE_NAME secrets-scan /code --output-file /output/test_results.md --format markdown
    
    if [ -f "$TEST_DIR/output/test_results.md" ]; then
        echo -e "${GREEN}Markdown output test passed!${NC}"
    else
        echo -e "${RED}Markdown output test failed!${NC}"
        return 1
    fi
}

# Function to test help command
test_help() {
    echo -e "${BLUE}Testing help command...${NC}"
    
    docker run --rm $IMAGE_NAME --help
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Help command test passed!${NC}"
    else
        echo -e "${RED}Help command test failed!${NC}"
        return 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--test-dir)
            TEST_DIR="$2"
            shift 2
            ;;
        -c|--clean)
            CLEANUP_ONLY=true
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

# Check Docker
check_docker

# Clean up if requested
if [ "$CLEANUP_ONLY" = true ]; then
    cleanup
    exit 0
fi

# Run test suite
echo -e "${BLUE}Starting Gerion CLI Docker test suite...${NC}"
echo ""

# Clean up any existing test artifacts
cleanup

# Create test files
create_test_files

# Test Docker build
test_build

# Test help command
test_help

# Test secrets scan
test_secrets_scan

# Test SCA scan
test_sca_scan

# Test file output
test_file_output

echo ""
echo -e "${GREEN}All tests passed! 🎉${NC}"
echo ""
echo -e "${YELLOW}Test artifacts are in: $TEST_DIR${NC}"
echo -e "${YELLOW}To clean up, run: $0 --clean${NC}" 