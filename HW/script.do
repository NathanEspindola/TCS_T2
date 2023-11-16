if {[file isdirectory work]} { vdel -all -lib work }

vlib work
vmap work work

# AES
vcom -cover sbcefx  aes/aes_pkg.vhd
vcom -cover sbcefx  aes/aes_dec.vhd
vcom -cover sbcefx  aes/aes_enc.vhd
vcom -cover sbcefx  aes/aes_key_expansion.vhd
vcom -cover sbcefx  aes/aes_top.vhd

# BLOWFISH
vcom -cover sbcefx  blowfish/blowfish_bram_key.vhd
vcom -cover sbcefx  blowfish/blowfish_bram_p.vhd
vcom -cover sbcefx  blowfish/blowfish_bram_s0.vhd
vcom -cover sbcefx  blowfish/blowfish_bram_s1.vhd
vcom -cover sbcefx  blowfish/blowfish_bram_s2.vhd
vcom -cover sbcefx  blowfish/blowfish_bram_s3.vhd
vcom -cover sbcefx  blowfish/blowfish_top.vhd

# GOST
vcom -cover sbcefx  gost/bram_key.vhd
vcom -cover sbcefx  gost/bram_s0.vhd
vcom -cover sbcefx  gost/gost_top.vhd

# NOEKEON
vcom -cover sbcefx  noekeon/bram_rc.vhd
vcom -cover sbcefx  noekeon/noekeon_top.vhd

# SIMON
vcom -cover sbcefx  simon/bram_sub_keys.vhd
vcom -cover sbcefx  simon/simon_top.vhd

# XTEA
vcom -cover sbcefx  xtea/xtea_top.vhd

# XTEA DUPLEX
vcom -cover sbcefx  xtea_duplex/xtea_dec.vhd
vcom -cover sbcefx  xtea_duplex/xtea_enc.vhd
vcom -cover sbcefx  xtea_duplex/xtea_subkey_calc_dec.vhd
vcom -cover sbcefx  xtea_duplex/xtea_subkey_calc_enc.vhd
vcom -cover sbcefx  xtea_duplex/xtea_top_duplex.vhd

# T2
vlog -cover sbcefx cmsdk_ahb_crypt.v

# TB
vcom -cover sbcefx tb.vhd

vsim -voptargs="+acc" -coverage -t 10ps tb cmsdk_ahb_crypt

#set StdArithNoWarnings 1

add wave -position end sim:/tb/*
add wave -position end sim:/tb/cuv/mem_cipher
add wave -position end sim:/tb/cuv/mem_key
add wave -position end sim:/tb/cuv/mem_plan
add wave -position end sim:/tb/cuv/crypt_str
add wave -position end sim:/tb/cuv/crypt_fsm
add wave -position end sim:/tb/cuv/crypt_algo
add wave -position end sim:/tb/cuv/crypt_key
add wave -position end sim:/tb/cuv/crypt_plan
add wave -position end sim:/tb/cuv/crypt_e_d

run 1000 us

coverage report -output coverage_rep
coverag save coverage