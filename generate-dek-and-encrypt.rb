require 'rubygems'
require 'bundler/setup'

require 'aws-sdk-kms'
require 'openssl'

# Setup stuff

keyId = ENV['AWS_CMK_ARN']
text = '<data that needs to be encrypted>'

client = Aws::KMS::Client.new(region: 'ap-southeast-1')

cipher = OpenSSL::Cipher::AES.new(256, :CBC)

resp = client.generate_data_key({
  key_id: keyId,
  key_spec: 'AES_256'
})

# Let's generate a Data Encryption Key from KMS.

dek = resp.to_h[:plaintext]
dek_encrypted = resp.to_h[:ciphertext_blob]

puts "Data Encryption Key:"
puts dek.unpack('H*')

puts "Data Encryption Key (Encrypted):"
puts dek_encrypted.unpack('H*')

# Generation and configuration of cryptography stuff.
cipher = OpenSSL::Cipher::AES.new(256, :CBC)

cipher.encrypt
iv = cipher.random_iv
cipher.key = dek # Use the Data Encryption Key for the encryption operation.

# Encrypt the data.
encrypted = cipher.update(text) + cipher.final

puts "*" * 10

puts "Initialization Vector"
puts iv.unpack('H*')

puts "Data Ciphertext"
puts encrypted.unpack('H*')

# You can now save the data encryption key ciphertext (dek_encrypted), initialization vector (iv),
# and data ciphertext (encrypted) into your data store, but we won't cover it here.

# Let's ask KMS to decrypt the data encryption key ciphertext using the CMK.
retrieved_dek = client.decrypt({
  ciphertext_blob: dek_encrypted
})

puts "Decrypt DEK ciphertext"
puts retrieved_dek[:plaintext].unpack('H*')

# Let's try to reverse the process by decrypting.

decipher = OpenSSL::Cipher::AES.new(256, :CBC)
decipher.decrypt
decipher.key = retrieved_dek[:plaintext]
decipher.iv = iv

plain = decipher.update(encrypted) + decipher.final

puts "*" * 10

puts plain
