
python verifier/verifierlight.py --tapdir __testdata__/aes128/ --matchesfile __testdata__/aes128/enc_string_matches.txt

python verifier/verifier.py --searchterms __testdata__/aes128/searchterms.txt --readbuffers __testdata__/aes128/read_tap_buffers.txt.gz --writebuffers __testdata__/aes128/write_tap_buffers.txt.gz --dataidx 23

python verifier/verifierheavy.py --datdir . --searchterms searchterms.txt