require 'rubygems'
require 'bundler/setup'

require 'aws-sdk-kms'

keyId = ENV['AWS_CMK_ARN']

text = '<data that needs to be encrypted>'

client = Aws::KMS::Client.new(region: 'ap-southeast-1')

resp = client.encrypt({
  key_id: keyId,
  plaintext: text
})

puts 'Ciphertext:'
puts resp.ciphertext_blob.unpack('H*')
