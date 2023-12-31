--########################################################################################
--## Developer: Jack Sampford (j.w.sampford-15@student.lboro.ac.uk)                     ##
--##                                                                                    ##
--## Design name: aes                                                                   ##
--## Module name: aes_top - RTL                                                         ##
--## Target devices: ARM MPS2+ FPGA Prototyping Board                                   ##
--## Tool versions: Quartus Prime 19.1, ModelSim Intel FPGA Starter Edition 10.5b       ##
--##                                                                                    ##
--## Description: AES encryption/decryption core. Takes plaintext data in and creates   ##
--## ciphertext. Takes ciphertext data in and creates plaintext. Before encryption/     ##
--## decryption, key expansion must be completed by setting key_valid high and setting  ##
--## key_word_in to the key 32 bits at a time, most significant word first. Once key    ##
--## expansion is complete key_ready will be asserted, indicating encryption/decryption ##
--## can begin. The process for this is the same as key expansion; set relevant flag    ##
--## high, (data_valid for encryption, ciphertext_valid for decryption) and input data/ ##
--## ciphertext 32 bits at a time on data_word_in/ciphertext_word_in, then wait for the ##
--## relevant flag to be asserted (ciphertext_ready for encryption, data_ready for      ##
--## decryption) and read data out 32 bits at a time on either ciphertext_word_out or   ##
--## data_word_out signals.                                                             ##
--##                                                                                    ##
--## Dependencies: aes_key_expansion.vhd, aes_enc.vhd, aes_dec.vhd                      ##
--########################################################################################

-- Library declarations
LIBRARY IEEE;
USE IEEE.STD_LOGIC_1164.ALL;

-- Entity definition
ENTITY aes_top IS
    PORT(
        -- Clock and active low reset
        clk                 : IN  STD_LOGIC;
        reset_n             : IN  STD_LOGIC;

        -- Plaintext data input, one 32-bit word at a time
        data_word_in        : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
        -- Flag to enable data input
        data_valid          : IN  STD_LOGIC;

        -- Ciphertext data input, one 32-bit word at a time
        ciphertext_word_in  : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
        -- Flag to enable ciphertext data input
        ciphertext_valid    : IN  STD_LOGIC;

        -- Length of input key, 0, 1 or 2 for 128, 192 or 256 respectively
        key_length          : IN  STD_LOGIC_VECTOR(1 DOWNTO 0);

        -- Key input, one 32-bit word at a time
        key_word_in         : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
        -- Flag to enable key input
        key_valid           : IN  STD_LOGIC;

        -- Flag to indicate key expansion is complete and encryption/decryption can be started
        key_ready           : OUT STD_LOGIC;

        -- Ciphertext data output from encryption core, one 32-bit word at a time
        ciphertext_word_out : OUT STD_LOGIC_VECTOR(31 DOWNTO 0);
        -- Flag to indicate the beginning of ciphertext output
        ciphertext_ready    : OUT STD_LOGIC;

        -- Plaintext data output from decryption core, one 32-bit word at a time
        data_word_out       : OUT STD_LOGIC_VECTOR(31 DOWNTO 0);
        -- Flag to indicate the beginning of plaintext output
        data_ready          : OUT STD_LOGIC
    );
END ENTITY aes_top;

-- Architecture definition
ARCHITECTURE struct OF aes_top IS

    -- Signals to allow passing of subkeys between key expansion and encryption/decryption cores
    SIGNAL get_key_encryption    : STD_LOGIC;
    SIGNAL get_key_decryption    : STD_LOGIC;
    SIGNAL key_number_encryption : STD_LOGIC_VECTOR(5 DOWNTO 0);
    SIGNAL key_number_decryption : STD_LOGIC_VECTOR(5 DOWNTO 0);
    SIGNAL subkey_encryption     : STD_LOGIC_VECTOR(31 DOWNTO 0);
    SIGNAL subkey_decryption     : STD_LOGIC_VECTOR(31 DOWNTO 0);

    -- Key expansion component
    COMPONENT key_expansion IS
        PORT(
            clk              : IN  STD_LOGIC;
            reset_n          : IN  STD_LOGIC;
            key_length       : IN  STD_LOGIC_VECTOR(1 DOWNTO 0);
            key_word_in      : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
            key_valid        : IN  STD_LOGIC;
            get_key_a        : IN  STD_LOGIC;
            get_key_number_a : IN  STD_LOGIC_VECTOR(5 DOWNTO 0);
            get_key_b        : IN  STD_LOGIC;
            get_key_number_b : IN  STD_LOGIC_VECTOR(5 DOWNTO 0);
            expansion_done   : OUT STD_LOGIC;
            key_word_out_a   : OUT STD_LOGIC_VECTOR(31 DOWNTO 0);
            key_word_out_b   : OUT STD_LOGIC_VECTOR(31 DOWNTO 0)
        );
    END COMPONENT key_expansion;

    -- Encryption core component
    COMPONENT aes_enc IS
        PORT(
            clk            : IN  STD_LOGIC;
            reset_n        : IN  STD_LOGIC;
            data_word_in   : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
            data_valid     : IN  STD_LOGIC;
            key_length     : IN  STD_LOGIC_VECTOR(1 DOWNTO 0);
            key_word_in    : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
            get_key        : OUT STD_LOGIC;
            get_key_number : OUT STD_LOGIC_VECTOR(5 DOWNTO 0);
            data_ready     : OUT STD_LOGIC;
            data_word_out  : OUT STD_LOGIC_VECTOR(31 DOWNTO 0)
        );
    END COMPONENT aes_enc;

    -- Decryption core component
    COMPONENT aes_dec IS
        PORT(
            clk            : IN  STD_LOGIC;
            reset_n        : IN  STD_LOGIC;
            data_word_in   : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
            data_valid     : IN  STD_LOGIC;
            key_length     : IN  STD_LOGIC_VECTOR(1 DOWNTO 0);
            key_word_in    : IN  STD_LOGIC_VECTOR(31 DOWNTO 0);
            get_key        : OUT STD_LOGIC;
            get_key_number : OUT STD_LOGIC_VECTOR(5 DOWNTO 0);
            data_ready     : OUT STD_LOGIC;
            data_word_out  : OUT STD_LOGIC_VECTOR(31 DOWNTO 0)
        );
    END COMPONENT aes_dec;

BEGIN

    -- Instantiate key expansion component
    key_exp_inst : key_expansion
    PORT MAP(
        clk              => clk,
        reset_n          => reset_n,
        key_length       => key_length,
        key_word_in      => key_word_in,
        key_valid        => key_valid,
        get_key_a        => get_key_encryption,
        get_key_number_a => key_number_encryption,
        get_key_b        => get_key_decryption,
        get_key_number_b => key_number_decryption,
        expansion_done   => key_ready,
        key_word_out_a   => subkey_encryption,
        key_word_out_b   => subkey_decryption
    );

    -- Instantiate AES encryption component
    aes_enc_inst : aes_enc
    PORT MAP(
        clk            => clk,
        reset_n        => reset_n,
        data_word_in   => data_word_in,
        data_valid     => data_valid,
        key_length     => key_length,
        key_word_in    => subkey_encryption,
        get_key        => get_key_encryption,
        get_key_number => key_number_encryption,
        data_ready     => ciphertext_ready,
        data_word_out  => ciphertext_word_out
    );

    -- Instantiate AES decryption component
    aes_dec_inst : aes_dec
    PORT MAP(
        clk            => clk,
        reset_n        => reset_n,
        data_word_in   => ciphertext_word_in,
        data_valid     => ciphertext_valid,
        key_length     => key_length,
        key_word_in    => subkey_decryption,
        get_key        => get_key_decryption,
        get_key_number => key_number_decryption,
        data_ready     => data_ready,
        data_word_out  => data_word_out
    );

END struct;
