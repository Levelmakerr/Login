# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# # from six import text_type

# # class TokenGenerator(PasswordResetTokenGenerator):
# #     def _make_hash_value(self, user, timestamp):
# #         return(
# #              text_type(user.pk) + text_type(timestamp) + text_type(user.is_active)
# #         )
# # generate_token = TokenGenerator

# class TokenGenerator(PasswordResetTokenGenerator):
#     def _make_hash_value(self, user, timestamp):
#         return str(user.pk) + str(user.password) + str(timestamp)

# generate_token = TokenGenerator()

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import time

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from django.utils.crypto import salted_hmac

class TokenGenerator(PasswordResetTokenGenerator):
    def __init__(self):
        super().__init__()  # Ensure parent constructor is called

    def _make_hash_value(self, user, timestamp):
        # Custom token generation logic, e.g., concatenating user info
        return str(user.pk) + user.password + str(timestamp)

generate_token = TokenGenerator()





