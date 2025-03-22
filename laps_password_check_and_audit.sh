#!/bin/bash

<<ABOUT_THIS_SCRIPT
============================================================================

	Written by: Lorenzo Fittarelli
	- Senior System Engineer
	- Swiss IT Security AG
	- lorenzo.fittarelli@sits.ch
	
	Created on: 2 Sep 2023 - 09:41:08
	Modified on: 4 Sep 2023

	Changes:
	V 0.1 -> Created the script
	V 0.2 -> Beautified, added user inputs
	V 0.3 -> Corrected the "local_admin_account" variable command, to include ONLY
			 the managed admin account that is created during PreStage Enrollment
			 and not the one created during UIE
	

	Purpose:
	This script is aimed to automate the LAPS password check and audit
	for the management account you need to use.
	The job the script does is:
	- Get user input (JSS URL, username, password, computer ID)
	- Encrypts the credential to feed them to the bearer token auth request
    - Query the API for:
		- computer managementID
		- management admin user account name
		- management admin CURRENT password (that is, after it has been rotated)
		- audit who and when checked the passwords for the management admin account
	- Everything is then printed out to stdout for the Mac Admin to read and use

	Instructions:
	Run locally -> Run the script in Terminal, making sure to
	provide it the appropriate permissions (chmod)

===========================================================================
ABOUT_THIS_SCRIPT

# ===== UNcomment the below command only if you need to debug the script =====
# set -x

# Let script exit if a command fails
set -o errexit

# Let script exit if an unused variable is used
set -o nounset

####################################################################################################
#
# VARIABLES START SETUP
#
####################################################################################################

# Ask the user to enter the JSS URL
echo "Please enter the JSS URL: "
read jss_url

echo ""

JAMFURL="${jss_url}"

# Ask the user to enter the JSS Username
echo "Please enter the JSS Username: "
read jss_user

echo ""

JAMFUSER="${jss_user}"

# Ask the user to enter the JSS Password
echo "Please enter the JSS Password: "
read -s jss_pass

echo ""

JAMFPASS="${jss_pass}"

# Ask the user to enter the computer ID
# from Jamf: search for the computer -> from the General Tab -> "Jamf Pro Computer ID" 
echo "Please enter the Computer ID: "
read user_input

echo ""

# Store the user input into a variable to use into the URL
computer_id="${user_input}"

# Define the URL with the "computers-inventory-detail" endpoint, followed by the $computer_id variable
computer_inventory_detail_url="${JAMFURL}/api/v1/computers-inventory-detail/${computer_id}"

# Define the URL with the "local-admin-password" endpoint for later use (to check the user name, the password and to audit)
local_admin_password_url="${JAMFURL}/api/v2/local-admin-password/"

##### DO NOT MODIFY BELOW HERE #####

# Base 64 Encryption - DO NOT Modify
B64=$(printf "${JAMFUSER}:${JAMFPASS}" | iconv -t ISO-8859-1 | base64 -i -)


####################################################################################################
#
# VARIABLES START SETUP
#
####################################################################################################


####################################################################################################
#
# FUNCTIONS START SETUP
#
####################################################################################################

getToken () {
	# Gets the token using the Base64 encoded credentials
	authToken=$(curl -s \
	--request POST \
	--url "${JAMFURL}/api/v1/auth/token" \
	--header "Accept: application/json"\
	--header "Authorization: Basic ${B64}" \
)
	
	# Extracts the token only (just the code) from the whole message displayed to output
	
	if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]; then
		api_token=$(/usr/bin/curl -X POST --silent -u "${JAMFUSER}:${JAMFPASS}" "${JAMFURL}/api/v1/auth/token" | python -c 'import sys, json; print json.load(sys.stdin)["token"]')
	else
		api_token=$(/usr/bin/curl -X POST --silent -u "${JAMFUSER}:${JAMFPASS}" "${JAMFURL}/api/v1/auth/token" | plutil -extract token raw -)
	fi
}


APITokenValidCheck() {
	# Verify that API authentication is using a valid token by running an API command
	# which displays the authorization details associated with the current API user. 
	# The API call will only return the HTTP status code.
	
	api_authentication_check=$(/usr/bin/curl --write-out %{http_code} --silent --output /dev/null "${JAMFURL}/api/v1/auth" --request GET --header "Authorization: Bearer ${api_token}")
}

CheckAndRenewAPIToken() {
	# Verify that API authentication is using a valid token by running an API command
	# which displays the authorization details associated with the current API user. 
	# The API call will only return the HTTP status code.
	
	APITokenValidCheck
	
	# If the api_authentication_check has a value of 200, that means that the current
	# bearer token is valid and can be used to authenticate an API call.
	
	if [[ ${api_authentication_check} == 200 ]]; then
		# If the current bearer token is valid, it is used to connect to the keep-alive endpoint. This will
		# trigger the issuing of a new bearer token and the invalidation of the previous one.
		
		if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]; then
			api_token=$(/usr/bin/curl "${JAMFURL}/api/v1/auth/keep-alive" --silent --request POST --header "Authorization: Bearer ${api_token}" | python -c 'import sys, json; print json.load(sys.stdin)["token"]')
		else
			api_token=$(/usr/bin/curl "${JAMFURL}/api/v1/auth/keep-alive" --silent --request POST --header "Authorization: Bearer ${api_token}" | plutil -extract token raw -)
		fi
	else
		# If the current bearer token is not valid, this will trigger the issuing of a new bearer token
		# using Basic Authentication.
		
		getToken
	fi
}

# Uncomment the below function only when needed

#InvalidateToken() {
#	# Verify that API authentication is using a valid token by running an API command
#	# which displays the authorization details associated with the current API user. 
#	# The API call will only return the HTTP status code.
#	
#	APITokenValidCheck
#	
#	# If the api_authentication_check has a value of 200, that means that the current
#	# bearer token is valid and can be used to authenticate an API call.
#	
#	if [[ ${api_authentication_check} == 200 ]]; then
#		# If the current bearer token is valid, an API call is sent to invalidate the token.
#		authToken=$(/usr/bin/curl "${JAMFURL}/api/v1/auth/invalidate-token" --silent  --header "Authorization: Bearer ${api_token}" -X POST)
#		
#		# Explicitly set value for the api_token variable to null.
#		api_token=""
#	fi
#}

####################################################################################################
#
# FUNCTIONS END SETUP
#
####################################################################################################

####################################################################################################
#
# START OF SCRIPT
#
####################################################################################################

# Get the API bearer token and check that it's valid

	getToken
	APITokenValidCheck
	
# Store in a variable the computer managementID (that is visible ONLY via API)	
	computer_management_Id=$(curl -s -X 'GET' "${computer_inventory_detail_url}" -H 'accept: application/json' -H "Authorization: Bearer ${api_token}" | awk '/managementId/ {print $3}' | sed 's/\"//g' | sed 's/\,//g')
	
	# Check that the computer managementId is not empty = wrong Computer ID
	if [[ -z "${computer_management_Id}" ]]
	then
		echo "No managementID found. Please ensure that the computer ID you entered is correct"
		exit 1
	fi	
	
	echo "The management ID is: ${computer_management_Id}"

# Store in a variable the local admin account (I'm printing the first line only as there is a second management account (UIE) but it's not the one we want to use - you can modify the below command based on your needs.)	
	local_admin_account=$(curl -s -X 'GET' "${local_admin_password_url}${computer_management_Id}/accounts" -H 'accept: application/json' -H "Authorization: Bearer ${api_token}" | grep -A2 'username' | grep -B1 'MDM' | head -n1 | awk '/username/ {print $3}' | sed 's/[",]//g')
	
	#if [[ "$local_admin_account" == *"macadmin2"* ]] || [[ "$local_admin_account" == *"localadmin"* ]];
	#then
	#	echo "${local_admin_account}"	
	#fi
	
	echo "The management account is: ${local_admin_account}"

# Store in a variable the computer name that is then printed to the user, for transparency 	
	computer_name=$(curl -s -X 'GET' "${computer_inventory_detail_url}" -H 'accept: application/json' -H "Authorization: Bearer ${api_token}" | grep -i -A2 'general' | awk '/name/ {print $3}' | sed 's/\"//g' | sed 's/\,//g')
	
	echo "The computer name is: ${computer_name}"
	
# Store in a variable the CURRENT password of the management admin account	
	current_password=$(curl -s -X 'GET' "${local_admin_password_url}${computer_management_Id}/account/${local_admin_account}/password" -H 'accept: application/json' -H "Authorization: Bearer ${api_token}" | awk '/password/ {print $3}' | sed 's/\"//g')

# Show to the user the management admin account username and CURRENT password
	echo "The current password of ${local_admin_account} is: ${current_password}"

# Just to be on the safe side, check and renew the API bearer token	
	CheckAndRenewAPIToken
	
# Start the audit of the password checks	
	echo "------------"
	echo ""
	echo "Auditing below who and when checked the password on device with ID: ${computer_id}."
	echo ""
	
# Very ugly command, but does the job to tidy up the output in nicer and more human readable manner	
	curl -s -X 'GET' "${local_admin_password_url}${computer_management_Id}/account/${local_admin_account}/audit" -H 'accept: application/json' -H "Authorization: Bearer ${api_token}" | sed -E 's/{/-----/g' | sed 's/},//g' | sed 's/}//g' | sed 's/]//g' | sed 's/\[//g' | sed 's/\,//g' | sed 's/\"password\"/Password/g' | sed 's/\"results\" \:  \-\-\-\-\-//g' | sed 's/\"totalCount\"/Total Count/g' | sed 's/\"dateLastSeen\"/Date Last Seen/g' | sed 's/\"expirationTime\"/Expiration Time/g' | sed 's/\"audits\" \:  \-\-\-\-\-//g' | sed 's/\"dateSeen\"/Seen on Date/g' | sed 's/\"viewedBy\"/Viewed By/g' | sed 's/\"//g'
	
	echo ""
	echo "End of audit."
	echo "------------"


####################################################################################################
#
# END OF SCRIPT
#
####################################################################################################

