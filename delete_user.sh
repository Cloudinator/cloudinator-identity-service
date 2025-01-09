#!/bin/bash

# GitLab configuration
GITLAB_URL="https://git.cloudinator.cloud/api/v4"
GITLAB_TOKEN="glpat-ovxQNbYcpE6-reMRMxRx"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to delete a user
delete_user() {
    local user_id=$1
    echo -e "\n${YELLOW}Attempting to delete user ID: $user_id${NC}"

    response=$(curl -s -w "\n%{http_code}" --request DELETE \
        --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
        "$GITLAB_URL/users/$user_id")

    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | sed '$d')

    case $http_code in
        204)
            echo -e "${GREEN}Successfully deleted user ID: $user_id${NC}"
            ;;
        404)
            echo -e "${RED}Error: User not found (404)${NC}"
            ;;
        401)
            echo -e "${RED}Error: Unauthorized. Check your token (401)${NC}"
            ;;
        *)
            echo -e "${RED}Error: Unexpected response (HTTP $http_code)${NC}"
            echo "Response: $response_body"
            ;;
    esac
}

# Main script
echo "GitLab User Management Script"
echo "----------------------------"

# Check if user ID is provided as a parameter
if [ -z "$1" ]; then
    echo -e "${RED}Error: No user ID provided. Please provide a user ID as a parameter.${NC}"
    exit 1
fi

user_id=$1
delete_user "$user_id"

echo -e "\n${GREEN}Script completed. Goodbye!${NC}"
