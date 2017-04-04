# address_searcher

go get github.com/mr-tron/address_searcher
go build -o  ./searcher github.com/mr-tron/address_searcher
./searcher  dash 'ololo|trulyalya' | grep -E --colour 'ololo|trulyalya'
