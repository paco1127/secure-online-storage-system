from email_validator import validate_email, EmailNotValidError

def is_vaild_email(email):
    '''Check if the email is valid using email_validator library.'''
    try:
        validate_email(email)
        return True
    except EmailNotValidError as e:
        return False
