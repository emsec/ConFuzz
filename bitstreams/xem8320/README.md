# leds_test.bit 
- Original bitstream generated with Vivado
- If the design is loaded correctly, LED0 and LED2 should light up

# leds_test_only_fabric.bit
- Contains only the fabric without header, footer, or anything else
- This fabric can be used to test the RSA primitives

# write_fdri bitstreams
- Write three frames of fabric data to the FDRI register

# bbram_test_key bitstreams
- Require the test_key.nky from the static folder to be written to the BBRAM

# dec bitstreams
- Decrypted versions of the respective encrypted ones
