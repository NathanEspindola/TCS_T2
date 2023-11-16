--------------------------------------
-- Library
--------------------------------------
library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;

--------------------------------------
-- Entity
--------------------------------------
entity blowfish_bram_s2 is
  port (
    clk    : in  std_logic;
    we     : in  std_logic;
    addr   : in  std_logic_vector(7 downto 0);
    data_i : in  std_logic_vector(31 downto 0);
    data_o : out std_logic_vector(31 downto 0)
  );
end entity;

--------------------------------------
-- Architecture
--------------------------------------
architecture blowfish_bram_s2 of blowfish_bram_s2 is
  type ram_type is array (0 to 255) of std_logic_vector(31 downto 0);
  signal RAM : ram_type := (
   x"E93D5A68",x"948140F7",x"F64C261C",x"94692934",x"411520F7",x"7602D4F7",x"BCF46B2E",x"D4A20068",
   x"D4082471",x"3320F46A",x"43B7D4B7",x"500061AF",x"1E39F62E",x"97244546",x"14214F74",x"BF8B8840",
   x"4D95FC1D",x"96B591AF",x"70F4DDD3",x"66A02F45",x"BFBC09EC",x"03BD9785",x"7FAC6DD0",x"31CB8504",
   x"96EB27B3",x"55FD3941",x"DA2547E6",x"ABCA0A9A",x"28507825",x"530429F4",x"0A2C86DA",x"E9B66DFB",
   x"68DC1462",x"D7486900",x"680EC0A4",x"27A18DEE",x"4F3FFEA2",x"E887AD8C",x"B58CE006",x"7AF4D6B6",
   x"AACE1E7C",x"D3375FEC",x"CE78A399",x"406B2A42",x"20FE9E35",x"D9F385B9",x"EE39D7AB",x"3B124E8B",
   x"1DC9FAF7",x"4B6D1856",x"26A36631",x"EAE397B2",x"3A6EFA74",x"DD5B4332",x"6841E7F7",x"CA7820FB",
   x"FB0AF54E",x"D8FEB397",x"454056AC",x"BA489527",x"55533A3A",x"20838D87",x"FE6BA9B7",x"D096954B",
   x"55A867BC",x"A1159A58",x"CCA92963",x"99E1DB33",x"A62A4A56",x"3F3125F9",x"5EF47E1C",x"9029317C",
   x"FDF8E802",x"04272F70",x"80BB155C",x"05282CE3",x"95C11548",x"E4C66D22",x"48C1133F",x"C70F86DC",
   x"07F9C9EE",x"41041F0F",x"404779A4",x"5D886E17",x"325F51EB",x"D59BC0D1",x"F2BCC18F",x"41113564",
   x"257B7834",x"602A9C60",x"DFF8E8A3",x"1F636C1B",x"0E12B4C2",x"02E1329E",x"AF664FD1",x"CAD18115",
   x"6B2395E0",x"333E92E1",x"3B240B62",x"EEBEB922",x"85B2A20E",x"E6BA0D99",x"DE720C8C",x"2DA2F728",
   x"D0127845",x"95B794FD",x"647D0862",x"E7CCF5F0",x"5449A36F",x"877D48FA",x"C39DFD27",x"F33E8D1E",
   x"0A476341",x"992EFF74",x"3A6F6EAB",x"F4F8FD37",x"A812DC60",x"A1EBDDF8",x"991BE14C",x"DB6E6B0D",
   x"C67B5510",x"6D672C37",x"2765D43B",x"DCD0E804",x"F1290DC7",x"CC00FFA3",x"B5390F92",x"690FED0B",
   x"667B9FFB",x"CEDB7D9C",x"A091CF0B",x"D9155EA3",x"BB132F88",x"515BAD24",x"7B9479BF",x"763BD6EB",
   x"37392EB3",x"CC115979",x"8026E297",x"F42E312D",x"6842ADA7",x"C66A2B3B",x"12754CCC",x"782EF11C",
   x"6A124237",x"B79251E7",x"06A1BBE6",x"4BFB6350",x"1A6B1018",x"11CAEDFA",x"3D25BDD8",x"E2E1C3C9",
   x"44421659",x"0A121386",x"D90CEC6E",x"D5ABEA2A",x"64AF674E",x"DA86A85F",x"BEBFE988",x"64E4C3FE",
   x"9DBC8057",x"F0F7C086",x"60787BF8",x"6003604D",x"D1FD8346",x"F6381FB0",x"7745AE04",x"D736FCCC",
   x"83426B33",x"F01EAB71",x"B0804187",x"3C005E5F",x"77A057BE",x"BDE8AE24",x"55464299",x"BF582E61",
   x"4E58F48F",x"F2DDFDA2",x"F474EF38",x"8789BDC2",x"5366F9C3",x"C8B38E74",x"B475F255",x"46FCD9B9",
   x"7AEB2661",x"8B1DDF84",x"846A0E79",x"915F95E2",x"466E598E",x"20B45770",x"8CD55591",x"C902DE4C",
   x"B90BACE1",x"BB8205D0",x"11A86248",x"7574A99E",x"B77F19B6",x"E0A9DC09",x"662D09A1",x"C4324633",
   x"E85A1F02",x"09F0BE8C",x"4A99A025",x"1D6EFE10",x"1AB93D1D",x"0BA5A4DF",x"A186F20F",x"2868F169",
   x"DCB7DA83",x"573906FE",x"A1E2CE9B",x"4FCD7F52",x"50115E01",x"A70683FA",x"A002B5C4",x"0DE6D027",
   x"9AF88C27",x"773F8641",x"C3604C06",x"61A806B5",x"F0177A28",x"C0F586E0",x"006058AA",x"30DC7D62",
   x"11E69ED7",x"2338EA63",x"53C2DD94",x"C2C21634",x"BBCBEE56",x"90BCB6DE",x"EBFC7DA1",x"CE591D76",
   x"6F05E409",x"4B7C0188",x"39720A3D",x"7C927C24",x"86E3725F",x"724D9DB9",x"1AC15BB4",x"D39EB8FC",
   x"ED545578",x"08FCA5B5",x"D83D7CD3",x"4DAD0FC4",x"1E50EF5E",x"B161E6F8",x"A28514D9",x"6C51133C",
   x"6FD5C7E7",x"56E14EC4",x"362ABFCE",x"DDC6C837",x"D79A3234",x"92638212",x"670EFA8E",x"406000E0");

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
