echo "1st header start"
RUST_LOG=info cargo run --release -- --execute --n 0 --header "01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed"
RUST_LOG=info cargo run --release -- --prove   --n 0 --header "01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed"
echo "1st header end"
echo
echo

echo "2nd header start"
RUST_LOG=info cargo run --release -- --execute --n 1 --header "010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b"
RUST_LOG=info cargo run --release -- --prove --n 1 --header "010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b"
echo "2nd header end"
echo
echo

echo "3rd header start"
RUST_LOG=info cargo run --release -- --execute --n 2 --header "010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4"
RUST_LOG=info cargo run --release -- --prove --n 2 --header "010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4"
echo "3rd header end"