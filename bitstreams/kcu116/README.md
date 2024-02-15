# leds_rsa.bit, leds_rsa_encrypted.bit, and leds_rsa_rolling_keys.bit
- Original bitstreams generated with Vivado
- If the design is loaded correctly, LED0 and LED2 should light up
- These were example bitstreams to develop the RSA primitives

# leds_rsa_only_fabric.bit
- Contains only the fabric without header, footer, or anything else
- This fabric can be used to test the RSA primitives

# leds_rsa_attack.bit 
- Original leds_rsa.bit bitstream including the necessary commands for the JustSTART attack (cf. Section 5.2 in paper)
