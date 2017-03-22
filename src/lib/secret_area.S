        .data

	.globl secret_area
secret_area:
__primary_key_secret_start:
        .incbin "primary_key.secret"
__primary_key_secret_end:

__passphrase_secret_start:
        .incbin "passphrase.secret"
__passphrase_secret_end:

	.globl secret_area_size
secret_area_size:
	.int __primary_key_secret_end - __primary_key_secret_start
	.int __passphrase_secret_end - __passphrase_secret_start
