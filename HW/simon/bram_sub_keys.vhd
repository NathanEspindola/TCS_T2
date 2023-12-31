-- FILE NAME : bram_sub_keys.vhd
-- STATUS    : Implementation of BRAM block
-- AUTHORS   : Nicolas Silva Moura
-- E-mail    : nicolas.moura@edu.pucrs.br
--------------------------------------------------------------------------------
-- RELEASE HISTORY
-- VERSION   DATE         DESCRIPTION
-- 1.0       2021-10-10   Initial version of the BRAM.
--------------------------------------------------------------------------------
--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity bram_sub_keys is
  port (
    clk    : in  std_logic;
    we     : in  std_logic;
    addr   : in  std_logic_vector(6 downto 0);
    data_i : in  std_logic_vector(63 downto 0);
    data_o : out std_logic_vector(63 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture bram_sub_keys of bram_sub_keys is
  type ram_type is array (0 to 71) of std_logic_vector(63 downto 0);
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