-- PUCRS - Pontifícia Universidade Católica do Rio Grande do Sul
-- Escola Politécnica | Engenharia da Computação
-- Teste e Confiabilidade de Sistemas
-- Trabalho 2 - Elaboração de um TB para teste de cobertura de um módulo de Criptografia
-- Professor Iaçanã Ianiski Weber
-- Alunos: Nathan Espindola e Wiliam Oliveira
-- Data: 15/11/2023

library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_unsigned.all;
use IEEE.numeric_std.all;
use IEEE.std_logic_textio.all;
use std.textio.all;

entity tb is
end entity tb;   

architecture tb_architecture of tb is
    signal clk : std_logic := '0'; 
	signal rst : std_logic := '0';
    signal sel : std_logic := '0'; --Sinal de controle para startar o modulo, 1 para start
    signal ready_in : std_logic := '0'; 
    signal addr : std_logic_vector(31 downto 0) := X"00000000"; --Sinal que controla os estágios (CRYPT_START, CRYPT_READY, CRYPT_CONFIG, CRYPT_KEY, CRYPT_PLAN, CRYPT_CIPHER)
    signal write_in : std_logic := '0'; --Sinal para sinalizar se é leitura(0) ou escrita(1)
    signal data_in : std_logic_vector(31 downto 0) := X"00000000";
    signal ready_out : std_logic := '0';
    signal esp : std_logic := '0';
    signal dataout : std_logic_vector(31 downto 0) := X"00000000";

    file parameters, results : text;

begin
    cuv: entity work.cmsdk_ahb_crypt
    port map
    (
        hsel_i => sel,
        hclk => clk,
        hreset_n => rst,
        hready_i => ready_in,
        haddr_i => addr,
        hwrite_i => write_in,
        hwdata_i => data_in,
        hreadyout_o => ready_out,
        hresp_o => esp,
        hrdata_o => dataout
    );

    -- Gerador de clock
    cryptclk : process
    begin
        clk <= not clk;
            wait for 5 ns;
    end process;
    
    crypt : process
        variable readparameters, writeresult : line;
        variable keysize : std_logic_vector(1 downto 0);
        variable plansize : std_logic;
        variable key1, key2, key3, key4, key5, key6, key7, key8, plan1, plan2, plan3, plan4, config : std_logic_vector(31 downto 0);
        variable dataout1, dataout2, dataout3, dataout4 : std_logic_vector(31 downto 0);
        variable space : character;

	begin
        file_open(parameters, "Parameters.txt", read_mode);
        file_open(results, "CryptResults.txt", write_mode);
       
        while not endfile(parameters) loop
            readline(parameters, readparameters);
            read(readparameters, keysize);
            read(readparameters, space);
            read(readparameters, plansize);
            read(readparameters, space);
            read(readparameters, key1);
            read(readparameters, space);
            read(readparameters, key2);
            read(readparameters, space);
            read(readparameters, key3);
            read(readparameters, space);
            read(readparameters, key4);
            read(readparameters, space);
            read(readparameters, key5);
            read(readparameters, space);
            read(readparameters, key6);
            read(readparameters, space);
            read(readparameters, key7);
            read(readparameters, space);
            read(readparameters, key8);
            read(readparameters, space);
            read(readparameters, plan1);
            read(readparameters, space);
            read(readparameters, plan2);
            read(readparameters, space);
            read(readparameters, plan3);
            read(readparameters, space);
            read(readparameters, plan4);
            read(readparameters, space);
            read(readparameters, config);

-- SIGNAL RESET --
            rst <= '0';
            sel <= '0';
            write_in <= '0';
                wait for 100 ns;
            rst <= '1';
                wait for 20 ns;
            
-- CRYPT START | KEY ORGANAZING
            if (keysize = "00") then -- 128 BITS
                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key1;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key2;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key3;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key4;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 20 ns;

            elsif (keysize = "01") then -- 192 BITS
                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key1;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key2;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key3;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key4;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key5;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key6;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 20 ns;

            elsif (keysize = "10") then -- 256 BITS
                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key1;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key2;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key3;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key4;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key5;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key6;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key7;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"00009000";
                data_in <= key8;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 20 ns;
            end if;
            
-- PLAN ORGANIZING
            if (plansize = '0') then -- 64 BITS
                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan1;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan2;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

            elsif(plansize = '1') then -- 128 BITS
                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan1;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan2;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan3;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 10 ns;

                sel <= '1';
                write_in <= '1';
                addr <= x"0000B000";
                data_in <= plan4;
                    wait for 10 ns;

                sel <= '0';
                write_in <= '0';
                    wait for 20 ns;
            end if;
            
-- CONFIGURATION
-- FIRST 24 BITS <= 0
-- 8 BITS REMAINING
    -- ALGORTIHM (4 BITS)
    -- KEY (2 BITS)
    -- PLAN (1 BIT)
    -- OPERATION (1 BIT) | ENCRYPTION => 1 | DECRYPTION => 0

            sel <= '1';
            write_in <= '1';
            addr <= x"00007000";
            data_in <= config;
                wait for 10 ns;

            sel <= '0';
            write_in <= '0';
                wait for 20 ns;
            
-- CRYPT_START
            sel <= '1';
            write_in <= '1';
            addr <= x"00003000";
                wait for 10 ns;

            sel <= '0';
            write_in <= '0';
                wait for 20 ns;
            
-- CRYPT_READY | IF DATAOUT = 0 THEN CONTINUE; IF = 1 THEN IT CAN BE READ
            sel <= '1';
            write_in <= '0';
            addr <= x"00005000";
                wait for 10 ns;

            while (dataout /= x"00000001")  loop
                wait for 10 ns;
            end loop;
            
            sel <= '0';
            write_in <= '0';
                wait for 20 ns;

-- CIPHER | DATAOUT RESULT
            sel <= '1';
            write_in <= '0';
            addr <= x"0000D000";
                wait for 10 ns;
            dataout1 := dataout;
                wait for 10 ns;
            dataout2 := dataout;
                wait for 10 ns;
            dataout3 := dataout;
                wait for 10 ns;
            dataout4 := dataout;

            write(writeresult, dataout1);
            write(writeresult, string'(" "));
            write(writeresult, dataout2);
            write(writeresult, string'(" "));
            write(writeresult, dataout3);
            write(writeresult, string'(" "));
            write(writeresult, dataout4);
            writeline(results, writeresult);

        end loop;

        file_close(results);
        file_close(parameters);
        
        rst <= '0';
        sel <= '0';
		    wait;
    end process crypt;

end architecture tb_architecture;