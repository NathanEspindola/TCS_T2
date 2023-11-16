--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_p is
  port (
    clk     : in  std_logic;
    we      : in  std_logic;
    addr    : in  std_logic_vector(4 downto 0);
    data_i  : in  std_logic_vector(31 downto 0);
    data_o  : out std_logic_vector(31 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_bram_p of blowfish_bram_p is
  type ram_type is array (0 to 31) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (
   x"243F6A88",x"85A308D3",x"13198A2E",x"03707344",x"A4093822",x"299F31D0",x"082EFA98",x"EC4E6C89",
   x"452821E6",x"38D01377",x"BE5466CF",x"34E90C6C",x"C0AC29B7",x"C97C50DD",x"3F84D5B5",x"B5470917",
   x"9216D5D9",x"8979FB1B",x"00000000",x"00000000",x"00000000",x"00000000",x"00000000",x"00000000",
   x"00000000",x"00000000",x"00000000",x"00000000",x"00000000",x"00000000",x"00000000",x"00000000");

begin

  process (clk)
  begin
    if falling_edge(clk) then
      if (we = '1') then
        RAM(conv_integer(addr)) <= data_i;
      end if;
    end if;
  end process;

  data_o <= RAM(conv_integer(addr));

end architecture;
