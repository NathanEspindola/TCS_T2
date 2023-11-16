--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_top is
  port (
         -- Clock and active low reset
         clk                 : in  std_logic;
         reset_n             : in  std_logic;
         -- Switch to enable encryption or decryption, 1 for encryption 0 for decryption
         encryption          : in  std_logic;
         -- Length of input key, 0, 1 or 2 for 128, 192 or 256 respectively
         key_length          : in  std_logic_vector(1 downto 0);
         -- Flag to enable key input
         key_valid           : in  std_logic;
         -- Key input, one 32-bit word at a time
         key_word_in         : in  std_logic_vector(31 downto 0);
         -- Flag to enable ciphertext input
         data_valid          : in  std_logic;
         -- Data input, one 32-bit word at a time
         data_word_in        : in  std_logic_vector(31 downto 0);
         -- Flag to indicate that encryption/decryption is processing
         crypt_busy_out      : out std_logic;
         -- Ciphertext output, one 64-bit word
         ciphertext_word_out : out std_logic_vector(31 downto 0);
         -- Flag to indicate the beginning of ciphertext output
         ciphertext_ready    : out std_logic
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_top of blowfish_top is
  --FSM
  signal st : integer range 0 to 11 := 0; --std_logic_vector (3 downto 0);
  signal st_cnt : std_logic_vector(6 downto 0) := (others => '0');
  signal st_stage : std_logic_vector(2 downto 0); --integer range 0 to 5;

  --Temporary signals
  signal data_word_low  : std_logic_vector(31 downto 0);
  signal data_word_high : std_logic_vector(31 downto 0);
  signal ciphertext_word_low  : std_logic_vector(31 downto 0);
  signal ciphertext_word_high : std_logic_vector(31 downto 0);

  --ENC Loop signals
  signal data_lp, data_rp : std_logic_vector (31 downto 0);
  signal ss1, ss2, sout1, sout2 : std_logic_vector (31 downto 0);
  signal counter : integer range 0 to 16; --Counting to control loop reading

  --DEC Loop signals
  signal counterd : integer range 1 to 17;
  signal s_sout1, s_sout2 : std_logic_vector(31 downto 0);

  --RAM signals
  type PKEYS is array (0 to 17) of std_logic_vector(31 downto 0);
  signal p_data_ram : PKEYS;
  signal p_data_o   : std_logic_vector(31 downto 0);
  signal max_keys   : std_logic_vector(2 downto 0);
  signal key_cnt    : std_logic_vector(2 downto 0);
  signal key_addr   : std_logic_vector(2 downto 0) := (others => '0');
  signal key_data_o : std_logic_vector(31 downto 0);
  signal s0_we      : std_logic;
  signal s1_we      : std_logic;
  signal s2_we      : std_logic;
  signal s3_we      : std_logic;
  signal s0_addr    : std_logic_vector(7 downto 0) := (others => '0');
  signal s1_addr    : std_logic_vector(7 downto 0) := (others => '0');
  signal s2_addr    : std_logic_vector(7 downto 0) := (others => '0');
  signal s3_addr    : std_logic_vector(7 downto 0) := (others => '0');
  signal s0_data_i  : std_logic_vector(31 downto 0);
  signal s1_data_i  : std_logic_vector(31 downto 0);
  signal s2_data_i  : std_logic_vector(31 downto 0);
  signal s3_data_i  : std_logic_vector(31 downto 0);
  signal s0_data_o  : std_logic_vector(31 downto 0);
  signal s1_data_o  : std_logic_vector(31 downto 0);
  signal s2_data_o  : std_logic_vector(31 downto 0);
  signal s3_data_o  : std_logic_vector(31 downto 0);
  signal s0_ref_data_o : std_logic_vector(31 downto 0);
  signal s1_ref_data_o : std_logic_vector(31 downto 0);
  signal s2_ref_data_o : std_logic_vector(31 downto 0);
  signal s3_ref_data_o : std_logic_vector(31 downto 0);
  signal bram_flag  : std_logic;
  signal bram_cleaned : std_logic;
  signal bram_addr  : std_logic_vector(7 downto 0) := (others => '0');
  signal bram_data  : std_logic_vector(31 downto 0);

begin

  ------------------------------------
  -- BRAMs
  ------------------------------------
  BRAM_KEY: entity work.blowfish_bram_key
  port map(
    clk     => clk,
    we      => key_valid,
    addr    => key_addr,
    data_i  => key_word_in,
    data_o  => key_data_o
  );

  BRAM_P: entity work.blowfish_bram_p
  port map(
    clk     => clk,
    we      => '0',
    addr    => st_cnt(4 downto 0),
    data_i  => (others => '0'),
    data_o  => p_data_o
  );

  BRAM_0: entity work.blowfish_bram_s0
  port map(
    clk     => clk,
    we      => s0_we,
    addr    => s0_addr,
    data_i  => s0_data_i,
    data_o  => s0_data_o
  );

  BRAM_1: entity work.blowfish_bram_s1
  port map(
    clk     => clk,
    we      => s1_we,
    addr    => s1_addr,
    data_i  => s1_data_i,
    data_o  => s1_data_o
  );

  BRAM_2: entity work.blowfish_bram_s2
  port map(
    clk     => clk,
    we      => s2_we,
    addr    => s2_addr,
    data_i  => s2_data_i,
    data_o  => s2_data_o
  );

  BRAM_3: entity work.blowfish_bram_s3
  port map(
    clk     => clk,
    we      => s3_we,
    addr    => s3_addr,
    data_i  => s3_data_i,
    data_o  => s3_data_o
  );

  BRAM_0_REF: entity work.blowfish_bram_s0
  port map(
    clk     => clk,
    we      => '0',
    addr    => bram_addr,
    data_i  => (others => '0'),
    data_o  => s0_ref_data_o
  );

  BRAM_1_REF: entity work.blowfish_bram_s1
  port map(
    clk     => clk,
    we      => '0',
    addr    => bram_addr,
    data_i  => (others => '0'),
    data_o  => s1_ref_data_o
  );

  BRAM_2_REF: entity work.blowfish_bram_s2
  port map(
    clk     => clk,
    we      => '0',
    addr    => bram_addr,
    data_i  => (others => '0'),
    data_o  => s2_ref_data_o
  );

  BRAM_3_REF: entity work.blowfish_bram_s3
  port map(
    clk     => clk,
    we      => '0',
    addr    => bram_addr,
    data_i  => (others => '0'),
    data_o  => s3_ref_data_o
  );

  ------------------------------------
  -- Assignments
  ------------------------------------
  crypt_busy_out <= '1' when st >= 3 and st <= 10 else '0';

  key_addr <= key_cnt when (st = 3) else st_cnt(2 downto 0);

  ------------------------------------
  -- Processes
  ------------------------------------
  BRAM_CONTROL: process(clk, reset_n)
  begin
    if reset_n = '0' then
      bram_flag <= '0';
      bram_cleaned <= '0';
      bram_addr <= (others => '0');
      bram_data <= (others => '0');
      s0_we     <= '0';
      s1_we     <= '0';
      s2_we     <= '0';
      s3_we     <= '0';
      s0_addr   <= (others => '0');
      s1_addr   <= (others => '0');
      s2_addr   <= (others => '0');
      s3_addr   <= (others => '0');
      s0_data_i <= (others => '0');
      s1_data_i <= (others => '0');
      s2_data_i <= (others => '0');
      s3_data_i <= (others => '0');
    elsif falling_edge(clk) then

      --BRAM: Write
      if bram_cleaned = '0' then
        s0_we     <= '1';
        s1_we     <= '1';
        s2_we     <= '1';
        s3_we     <= '1';
        s0_addr   <= bram_addr;
        s1_addr   <= bram_addr;
        s2_addr   <= bram_addr;
        s3_addr   <= bram_addr;
        s0_data_i <= s0_ref_data_o;
        s1_data_i <= s1_ref_data_o;
        s2_data_i <= s2_ref_data_o;
        s3_data_i <= s3_ref_data_o;
        bram_addr <= bram_addr + 1;
        if bram_addr = 255 then
          bram_cleaned <= '1';
        end if;
      elsif (counter = 16 and st_stage = 3) then
        bram_flag <= '1';
        bram_data <= sout2;
        if st = 5 then
          s0_we     <= '1';
          s0_addr   <= (st_cnt & '0');
          s0_data_i <= sout1;
        end if;
        if st = 6 then
          s1_we     <= '1';
          s1_addr   <= (st_cnt & '0');
          s1_data_i <= sout1;
        end if;
        if st = 7 then
          s2_we     <= '1';
          s2_addr   <= (st_cnt & '0');
          s2_data_i <= sout1;
        end if;
        if st = 8 then
          s3_we     <= '1';
          s3_addr   <= (st_cnt & '0');
          s3_data_i <= sout1;
        end if;
      elsif bram_flag = '1' then
        bram_flag <= '0';
        bram_data <= (others => '0');
        if s0_we = '1' then
          s0_addr(0) <= '1';
          s0_data_i  <= bram_data;
        end if;
        if s1_we = '1' then
          s1_addr(0) <= '1';
          s1_data_i <= bram_data;
        end if;
        if s2_we = '1' then
          s2_addr(0) <= '1';
          s2_data_i <= bram_data;
        end if;
        if s3_we = '1' then
          s3_addr(0) <= '1';
          s3_data_i <= bram_data;
        end if;

      --BRAM: Read
      else
        s0_addr <= data_lp(31 downto 24);
        s1_addr <= data_lp(23 downto 16);
        s2_addr <= data_lp(15 downto  8);
        s3_addr <= data_lp( 7 downto  0);

        if s0_we = '1' then
          s0_we     <= '0';
          s0_data_i <= (others => '0');
        end if;
        if s1_we = '1' then
          s1_we     <= '0';
          s1_data_i <= (others => '0');
        end if;
        if s2_we = '1' then
          s2_we     <= '0';
          s2_data_i <= (others => '0');
        end if;
        if s3_we = '1' then
          s3_we     <= '0';
          s3_data_i <= (others => '0');
        end if;
      end if;
    end if;
  end process;

  -- FSM: Finite State Machine
  FSM: process (clk, reset_n)
  begin
    if reset_n = '0' then
      st       <= 0;
      st_cnt   <= (others => '0');
      st_stage <= (others => '0');
	  max_keys <= "011"; --default 128bit key
    elsif rising_edge(clk) then
      case st is
        -- Load key data input
        when 0 =>
	      if st_cnt = 0 then
		    if key_length = "10" then
		      max_keys <= "111"; --256bit
		    elsif key_length = "01" then
		      max_keys <= "101"; --192bit
		    else
			  max_keys <= "011"; --default 128bit key
            end if; 
          end if;
		
          if st_cnt = max_keys then
            st     <= st + 1;
            st_cnt <= (others => '0');
          elsif key_valid = '1' then
            st_cnt <= st_cnt + 1;
          end if;	  
		  
        -- Load ciphertext input
        when 1 =>
          if data_valid = '1' then
            if st_cnt = 1 then
              st     <= st + 1;
              st_cnt <= (others => '0');
            else
              st_cnt <= st_cnt + 1;
            end if;
          end if;

        -- Load key data input
        when 2 =>
          if bram_cleaned = '1' then
            st     <= st + 1;
          end if;

        -- Start to process the encryption/decryption
        when 3 =>
          if st_cnt = 17 then
            st     <= st + 1;
            st_cnt <= (others => '0');
          else
            st_cnt <= st_cnt + 1;
          end if;

        when 4 =>
          if (counter = 16 and st_stage = 3) then
            if st_cnt = 8 then
              st     <= st + 1;
              st_cnt <= (others => '0');
            else
              st_cnt <= st_cnt + 1;
            end if;
          end if;
          if (st_stage <= 2 or counter = 16) then
            st_stage <= st_stage + 1;
          else
            st_stage <= (others => '0');
          end if;

        -- Load S0, S1, S2, S3
        when 5 to 8 =>
          if (counter = 16 and st_stage = 3) then
            st_cnt <= st_cnt + 1;
            if st_cnt = 127 then
              st     <= st + 1;
            end if;
          end if;
          if (st_stage <= 2 or counter = 16) then
            st_stage <= st_stage + 1;
          else
            st_stage <= (others => '0');
          end if;
        when 9 =>
          if (counter = 16 and st_stage = 3) then
            st     <= st + 1;
          end if;
          if (st_stage <= 2 or counter = 16) then
            st_stage <= st_stage + 1;
          else
            st_stage <= (others => '0');
          end if;

        -- 11: conversion_complete
        when 10 =>
          st       <= st + 1;

        when 11 =>
          if st_cnt = 2 then
            st     <= 0;
            st_cnt <= (others => '0');
          else
            st_cnt <= st_cnt + 1;
          end if;

        when others => null;
      end case;
    end if;
  end process;

  -- IO data flow
  IO_DATA_FLOW: process (clk, reset_n)
  begin
    if reset_n = '0' then
      data_word_low  <= (others => '0');
      data_word_high <= (others => '0');
      ciphertext_ready     <= '0';
      ciphertext_word_out  <= (others => '0');
      ciphertext_word_low  <= (others => '0');
      ciphertext_word_high <= (others => '0');
    elsif rising_edge(clk) then

      --if st = 1 then
      if data_valid = '1' then
        if st_cnt = 0 then
          data_word_high <= data_word_in;
        else
          data_word_low  <= data_word_in;
        end if;
      end if;
      --end if;

      if st = 10 then
        if encryption = '1' then
          ciphertext_word_high <= sout1;
          ciphertext_word_low  <= sout2;
        else
          ciphertext_word_high <= s_sout2;
          ciphertext_word_low  <= s_sout1;
        end if;
      end if;

      if st = 11 then
        if st_cnt = 0 then
          ciphertext_ready     <= '1';
          ciphertext_word_out  <= ciphertext_word_high;
        elsif st_cnt = 1 then
          ciphertext_ready     <= '1';
          ciphertext_word_out  <= ciphertext_word_low;
        else
          ciphertext_ready     <= '0';
          ciphertext_word_out  <= (others => '0');
        end if;
      end if;

    end if;
  end process;

  SETKEYS: process (clk, reset_n) 
  begin
    if reset_n = '0' then
      p_data_ram <= (others => (others => '0'));
      key_cnt <= (others => '0');
    elsif rising_edge(clk) then

--    if st_cnt < 18 then --to have longer keys need to change how flags declare end of this section using arrays to store key
      if st = 3 then
        p_data_ram(conv_integer(st_cnt)) <= p_data_o xor key_data_o;
        if key_cnt = max_keys then
          key_cnt <= (others => '0');
        else
          key_cnt <= key_cnt + 1;
        end if;
      --Process delay for encryption loop
      elsif st = 4 then
        if (counter = 16 and st_stage = 3) then
          p_data_ram(conv_integer(st_cnt(3 downto 0) & '0')) <= sout1;
          p_data_ram(conv_integer(st_cnt(3 downto 0) & '1')) <= sout2;
        end if;
      end if;
    end if;
  end process;

  --Process the blowfish encryption rounds
  EncryptionRound: process (clk, reset_n)
  begin
    if reset_n = '0' then
      counter  <= 0;
      counterd <= 17;
      sout1   <= (others => '0');
      sout2   <= (others => '0');
      s_sout1 <= (others => '0');
      s_sout2 <= (others => '0');
      data_lp <= (others => '0');
      data_rp <= (others => '0');
    elsif rising_edge(clk) then
      if st_stage = 1 then -- and st_delay = '0' then
        counter  <= counter + 1;
        counterd <= counterd - 1;
      elsif st_stage = 4 then
        counter  <= 0;
        counterd <= 17;
      end if;

      if st_stage = 5 then
        sout1   <= (others => '0');
        sout2   <= (others => '0');
        s_sout1 <= (others => '0');
        s_sout2 <= (others => '0');
      elsif counter = 16 then
        sout1   <= data_lp xor p_data_ram(17); --left
        sout2   <= data_rp xor p_data_ram(16); --right
        s_sout1 <= data_rp xor p_data_ram(1);  --RIGHT
        s_sout2 <= data_lp xor p_data_ram(0);  --LEFT 
      end if;

      if counter <= 15 then
        if st_stage = 0 then
          if (st < 9 or encryption = '1') then
            data_lp <= ss1 xor p_data_ram(counter);
          elsif (st = 9 and encryption = '0')then
            data_lp <= ss1 xor p_data_ram(counterd);
          end if;
        end if;
        if st_stage = 1 then
          data_rp <= ss2 xor (((s0_data_o + s1_data_o) xor s2_data_o) + s3_data_o);
        end if;
      end if;
    end if;
  end process;

  --Control blowfish encryption inputs
  BLOWFISH_ENCRYPTION: process (clk, reset_n) 
  begin
    if reset_n = '0' then
      ss1 <= (others => '0');
      ss2 <= (others => '0');
    elsif rising_edge(clk) then
      if st_stage = 3 then
        ss1 <= data_rp;
        ss2 <= data_lp;
      elsif st_stage = 4 then
        if st < 9 then
          ss1 <= sout1;
          ss2 <= sout2;
        elsif st = 9 then
          ss1 <= data_word_high;
          ss2 <= data_word_low;
        else
          ss1 <= (others => '0');
          ss2 <= (others => '0');
        end if;
      end if;
    end if;
  end process;

end architecture;
