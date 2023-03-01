init:
	git clone --recurse-submodules https://github.com/TheFrozenFire/snark-jwt-verify
	npm install -g mocha
	npm install

prove: 
	cd test && mocha dkim.js

clean:
	rm -rf ./build_circuits/*