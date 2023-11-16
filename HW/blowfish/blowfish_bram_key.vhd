--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_key is
  port (
    clk     : in  std_logic;
    we      : in  std_logic;
    addr    : in  std_logic_vector(2 downto 0);
    data_i  : in  std_logic_vector(31 downto 0);
    data_o  : out std_logic_vector(31 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_bram_key of blowfish_bram_key is
  type ram_type is array (0 to 7) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (others => (others => '0'));

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
