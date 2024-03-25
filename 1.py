import requests
from lxml import html
from concurrent.futures import ThreadPoolExecutor
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39MnemonicGenerator, Bip39WordsNum
import time

def generate_unique_mnemonic(unique_mnemonics):
    while True:
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        if mnemonic not in unique_mnemonics:
            unique_mnemonics.add(mnemonic)
            return mnemonic

def generate_bip84_address_from_mnemonic(mnemonic):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44 = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    address = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    return address

urlbase = "https://ethereum.atomicwallet.io/api/v2/address/"
num_threads = 150
max_iterations = 1000000000000000000000000000000000000000000000000000000

def process_address(mnemonic, address, index):
    try:
        full_url = urlbase + address
        treetxid = requests.get(full_url).json()
        if treetxid:
            xVol = dict(treetxid)['balance']
            print(f"{index} :  {xVol}")
            if int(xVol) > 0:
                with open('win.txt', 'a') as file:
                    file.write(f"Mnemonic: {mnemonic}, eth: {xVol}\n")
    except Exception as e:
        print(f"Error processing address {address}: {e}")

def main():
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        unique_mnemonics = set()
        index = 1
        iterations = 0
        while iterations < max_iterations:
            mnemonic = generate_unique_mnemonic(unique_mnemonics)
            address = generate_bip84_address_from_mnemonic(mnemonic)
            executor.submit(process_address, mnemonic, address, index)
            index += 1
            iterations += 1
    end_time = time.time()
    print(f"Execution time: {end_time - start_time} seconds")

if __name__ == "__main__":
    main()
