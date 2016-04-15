#include <iostream>
#include <map>

using namespace std;

int main(){

	map<int,int> test;

	test[0] = 20;
	test[1] = 10;
	test[3]++;
	
	map<int, int>::iterator it;

	for(it = test.begin(); it != test.end(); it++)
	{
		cout << it->first << ":" << it->second << endl;
	}
	return 0;
}
