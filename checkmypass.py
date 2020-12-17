import requests
import hashlib
import sys

def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char # query returns full length hashed matching the first 5 characters
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code} check the API and try again')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for returned_hash, count in hashes:
		if returned_hash == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	#Check password if it exists in API response
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... you should change your password')
		else:
			print(f'{password} was NOT found, Carry on!')

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:])) #runs the script for each password provided in the command line after the file name, spearated by "space"
