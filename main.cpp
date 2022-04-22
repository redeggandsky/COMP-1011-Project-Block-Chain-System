#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include "SHA1.hpp"
#include "SHA1.cpp"
#include <cstring>
//#define ll long long
typedef long long ll;
using namespace std;

void int2char(char *s, int value){
	for(int i = 0; i < 10; i++)
		s[i] = value % 10 + '0', value /= 10;
}

void ll2char(char *s, ll value){
	for(int i = 0; i < 20; i++)
		s[i] = value % 10 + '0', value /= 10;
}

int char2int(char *s){
	int ans = 0;
	for(int i = 9; i >= 0; i--)
		ans = ans * 10 + s[i] - '0';
	return ans;
}

ll char2ll(char *s){
	ll ans = 0;
	for(int i = 19; i >= 0; i--)
		ans = ans * 10 + s[i] - '0';
	return ans;
}

int trans(char c){
	return (c <= '9' && c >= '0') ? c - '0' : c - 'a' + 10;
}

char trans(int c){
	//cout<<"trans:"<<c<<"  "<<(char)((c <= 9 && c >= 0) ? c + '0' : c + 'a' - 10)<<endl;
	return (c <= 9 && c >= 0) ? c + '0' : c + 'a' - 10;
}

inline ll lowbit(ll x) { // the lowest 1
	return x & -x;
}

inline int rand30(){
	return ((rand() % 32768) << 15) + (rand() % 32768);
}

inline ll big_mul(ll a, ll b, ll mod) {
    ll ans=a * b - (ll)(floor((long double)a * b / mod)) * mod;
    return (ans % mod + mod) % mod;
}

inline ll fast_pow(ll x, ll v, ll mod) {
	ll an = 1;
	while(v){
		if(v&1) an = big_mul(an, x, mod);
		x = big_mul(x, x, mod);
		v >>= 1;
	}
	return an;
}

inline bool Miller_Rabin(ll num, int T){ // test whether a big number "num" is a prime. num should <= INT_MAX
	//cout<<num<<endl;
	if(num == 2) return true;
	ll p = 0, q; // num - 1 = 2^p * q;
	ll tmp = lowbit(num-1); 
	q = num / tmp;
	while(tmp) p++, tmp >>= 1;
	// randome generate a number a, if num is a prime, a^{num-1} should be 1. Any number x^2 == 1 (mod num), x should be 1 or -1. 
	
	while(T--){
		ll a = rand30() % (num-2) + 2; // 2 ~ num
		a = fast_pow(a, q, num);
		for(int i = 0; i < p; i++){
			if(a * a % num == 1 && a != 1 && a != num-1){
				return false;
			}
			a = (a * a) % num;
		}
		if(a != 1) return false;
		//cout<<num<<endl;
	}
	return true;
}

inline ll random_big_prime(){
	while(1){
		ll x = rand30() + 998244353ll;
		if(Miller_Rabin(x, 5)) return x;
	}
}

ll gcd(ll a, ll b){
	if(b == 0) return a;
	return gcd(b, a % b);
}

void exgcd(ll a, ll b, ll &x, ll &y, ll mod){
	if(b == 0){
		x=1, y=0;
		return ;
	}
	exgcd(b, a%b, y, x, mod);
	y = ((y - big_mul((a / b) , x, mod)) % mod + mod) % mod;
}

struct Key{
	ll n, k;
	ll coding(ll info){
		return fast_pow(info, k, n);
	} 
};

inline void RSA(Key& private_key, Key& public_key){
	ll p1 = random_big_prime(), p2 = random_big_prime();
	while(p2 == p1) p2 = random_big_prime();
	ll phi = (p1-1) * (p2-1);
	ll cnt = rand30();
	while(gcd(cnt, phi) != 1){
		cnt = rand30();
	}
	ll x, y;
	exgcd(cnt, phi, x, y, phi);
	private_key.n = p1 * p2;
	private_key.k = x;
	public_key.n = p1 * p2;
	public_key.k = cnt;
}

inline void hashs(char *s, char *ans){
	SHA1 checksum;
	checksum.update(s);
	strcpy(ans, checksum.final().c_str());
}

inline void hashs(string s, char *ans){
	SHA1 checksum;
	checksum.update(s);
	strcpy(ans, checksum.final().c_str());
}

struct User{
	Key public_key;
	ll money;
	void display(){
		cout<<"Blance: "<<money<<" coins | Public key: ("<<public_key.n<<" "<<public_key.k<<") "<<endl;
	}
};

struct Info{
	char info[92] = {'\0'}; ll sign[11] = {0};
	/*
	"A" + Userid(10 digits) + PublicKey(40 digits) + Time(20 digits)
	"T" + Userid(10 digits) + PublicKey(40 digits) + Time(20 digits) + Userid(10 digits) + Money(10 digits)
	*/ 
	int op = 0;
	int userid = 0, userid2 = 0, money = 0;
	Key public_key;
	ll time;
	void decode_info(){
		userid = char2int(info+1);
		public_key.n = char2ll(info+11);
		public_key.k = char2ll(info+31);
		time = char2ll(info+51);
		if(info[0] == 'A')
			op = 1;
		if(info[0] == 'T')
		{
			op = 2;
			userid2 = char2int(info+71);
			money = char2int(info+81);
		}
	}
	void encode_info(){
		int2char(info+1, userid);
		//<<info+1<<endl;
		ll2char(info+11, public_key.n);
		//cout<<info+1<<endl;
		ll2char(info+31, public_key.k);
	//	cout<<info+1<<endl;
		ll2char(info+51, time);
	//	cout<<info+1<<endl;
		if(op == 1) info[0] = 'A';
		if(op == 2) {
			info[0] = 'T';
			int2char(info+71, userid2);
		//	cout<<info<<endl;
			int2char(info+81, money);
		//	cout<<info<<endl;
		}
	}
	void display(){
		if(op == 1){
			cout<<"UNIX Time: "<<time<<" | "<<"Add new user: "<<userid<<" | with public key: ("<<public_key.n<<" "<<public_key.k<<") "<<endl;
			cout<<"E-Signature: ";
			for(int i = 0; i < 10; i++)
				cout<<sign[i]<<" ";
			cout<<endl;
			cout<<".............................................................."<<endl;
		}
		if(op == 2){
			cout<<"UNIX Time: "<<time<<" | "<<" User: "<<userid<<" | with public key: ("<<public_key.n<<" "<<public_key.k<<") transfer "<<money<<" coins to user: "<<userid2<<endl;
			cout<<"E-Signature: ";
			for(int i = 0; i < 10; i++)
				cout<<sign[i]<<" ";
			cout<<endl;
			cout<<".............................................................."<<endl;
		}
	}
	bool verify(){
		char tmp[41] = {'\0'};
		hashs(info, tmp);
	//	cout<<info<<" --- "<<tmp<<endl;
	//	cout<<tmp<<" !!! "<<sign<<endl;
		int cnt = 0;
		for(int i = 0; i < 40; i+=4){
			//int x = trans(sign[i]);
			ll x = sign[cnt++];
			int y = trans(tmp[i]);
			for(int j = 1; j < 4; j++){
			//	x = (x << 4) + trans(sign[i+j]);
				y = (y << 4) + trans(tmp[i+j]);
			}
			x = fast_pow(x, public_key.k, public_key.n);
		//	cout<<x<<" ? "<<y<<endl;
			if(x == y) continue;
			return false;
		}
		return true;
	}
	void get_sign(Key private_key){
		char tmp[41];
		hashs(info, tmp);
		int cnt = 0;
		for(int i = 0; i < 40; i+=4){
			ll y = trans(tmp[i]);
			for(int j = 1; j < 4; j++)
				y = (y << 4) + trans(tmp[i+j]);
			y = fast_pow(y, private_key.k, private_key.n);
			//for(int j = 3; j >=0; j--)
			//	sign[i+j] = trans(y % 16), y /= 16;
			sign[cnt++] = y;
		}
	}
};

struct header{
	int block_id = 0; // block ID
	ll time; // unix time
	int nonce;
	int level = 2; // 
	char prev_hash[41] = {'\0'};
	char info_hash[41] = {'\0'};
	int userid; // the one who pass the PoW and get this block
	void block_hash(char *ans){
		char s[133];
		s[132] = '\0';
		int cnt = 0;
		int2char(s, block_id);
		ll2char(s+10, time);
		int2char(s+30, nonce);
		cnt = 40;
		s[cnt++] = level % 10 + '0';
		s[cnt++] = level / 10 + '0';
		cnt = 42;
		for(int i = 0; i < 40; i++)
			s[cnt++] = prev_hash[i];
		for(int i = 0; i < 40; i++)
			s[cnt++] = info_hash[i];
		int2char(s+cnt, userid);
		hashs(s, ans);
		//cout<<s<<endl;
	}
	void get_block_hash(){
		char ans[41];
		while(1){
			nonce = rand30();
			block_hash(ans);
			//cout<<nonce<<"  "<<ans<<endl;
			bool ok = 1;
			for(int i = 0; i < level; i++)
				if(ans[i] != '0'){
					ok = 0;
					break;
				}
			if(ok) break;
		}
	}
	void display(){
		cout<<"Block ID: "<<block_id<<" | Added UNIX time: "<<time<<" | Owned by user: "<<userid<<endl;
		cout<<"Nonce: "<<nonce<<" | Hard Level: "<<level<<endl;
		cout<<"Previous block's hash value:              "<<prev_hash<<endl;
		cout<<"Block's deal information's hash value:    "<<info_hash<<endl;
		char ans[41];
		block_hash(ans);
		cout<<"Block's hash value:                       "<<ans<<endl;
		cout<<"--------------------------------------------------------"<<endl;
	}
};

struct block_chain{
	vector<header> head;
	vector<Info> tmp_data;
	vector<vector<Info> > data;
	int user_count = 0, tmp_user_count = 0;
	vector<User> user;
	
	void add_block(ll Time, int Userid){
		header new_block;
		header last_block = head[head.size()-1];
		new_block.block_id = last_block.block_id + 1;
		last_block.block_hash(new_block.prev_hash);
		new_block.time = Time;
		new_block.userid = Userid;
		for(int i = 0; i < tmp_data.size(); i++){
			string tmp1(tmp_data[i].info);
			string tmp2(new_block.info_hash);
			string tmp = tmp1+tmp2;
			for(int j = 0; j < 10; j++)
				tmp += to_string(tmp_data[i].sign[j]);
			hashs(tmp, new_block.info_hash);
		}
		cout<<"Proof-of-Work..."<<endl;
		new_block.get_block_hash();
		cout<<"Proof-of-Work Passed"<<endl;
		
		data.push_back(tmp_data);
		tmp_data.clear();
		for(int i = 0; i < data[new_block.block_id].size(); i++){
			Info x = data[new_block.block_id][i];
			if(x.op == 1){
				User y;
				y.money = 0;
				y.public_key = x.public_key;
				user.push_back(y);
			}
			else if(x.op == 2){
				user[x.userid].money -= x.money;
				user[x.userid2].money += x.money;
			}
		}
		
		head.push_back(new_block);
		user_count = tmp_user_count;
		user[Userid].money += 100;
		cout<<"UNIX Time: "<<Time<<" | New block: "<<new_block.block_id<<" have been added by user: "<<Userid<<endl;
		cout<<"All the deals in transaction pool have been confirmed"<<endl;
	}
	void make_transfer(ll Time, int from_id, int to_id, int money){
		Key private_key;
		cout<<"Input user: "<<from_id<<" 's private key (x y) [input like: x y]: "<<endl;
		cin>>private_key.n>>private_key.k;
		Info new_deal;
		new_deal.op = 2;
		new_deal.userid = from_id;
		new_deal.userid2 = to_id;
		new_deal.money = money;
		new_deal.public_key = user[from_id].public_key;
		new_deal.time = Time;	
		new_deal.encode_info();	
		new_deal.get_sign(private_key);
		if(!new_deal.verify()){
			cout<<"Wrong Private Key! Failed to make a transfer! "<<endl;
			return ;
		}
		new_deal.display();
		tmp_data.push_back(new_deal);
	}
	void add_user(ll Time){
		Info new_deal;
		new_deal.op = 1;
		new_deal.userid = tmp_user_count++;
		Key public_key, private_key;
		RSA(private_key, public_key);
		new_deal.public_key = public_key;
		new_deal.time = Time;
		new_deal.encode_info();
		new_deal.get_sign(private_key);
		tmp_data.push_back(new_deal);
		new_deal.display();
		cout<<"NOTE: New userid: "<<tmp_user_count-1<<",  its private key: ("<<private_key.n<<" "<<private_key.k<<") "<<endl;
	}
	
	void init(){
		User user0; Key private_key0;
		RSA(private_key0, user0.public_key);
		user0.money = 100;
		Info X; X.op = 1; X.time = time(0);
		X.public_key = user0.public_key;
		X.userid = 0;
		X.encode_info();
		X.get_sign(private_key0);
		tmp_data.push_back(X);
		data.push_back(tmp_data);
		tmp_data.clear();
		
		header head0;
		head0.block_id = 0;
		head0.time = 21105092;
		string tmp1(data[0][0].info);
		string tmp2(head0.info_hash);
		string tmp = tmp1+tmp2;
		for(int j = 0; j < 10; j++)
			tmp += to_string(data[0][0].sign[j]);
	 	hashs(tmp, head0.info_hash);
		head0.userid = 0;
		head0.get_block_hash();
		head.push_back(head0);
		user.push_back(user0);
		user_count = tmp_user_count = 1;
	}
	void display(int i){
		cout<<"##################################################################################"<<endl;
		cout<<"Block's header:"<<endl;
		head[i].display();
		cout<<"Block's deal information:"<<endl;
		for(int j = 0; j < data[i].size(); j++){
			data[i][j].display();
		}
		cout<<"##################################################################################"<<endl;
	}
	void writefile(){
		ofstream file("data.txt", ios::out);
		file<<head.size()<<endl;;
		for(int i = 0; i < head.size(); i++){
			header x = head[i];
			file<<x.block_id<<" "<<x.nonce<<" "<<x.time<<" "<<x.userid<<" "<<x.level<<endl;
			file<<x.info_hash<<endl;
			if(i != 0)file<<x.prev_hash<<endl;
			file<<data[i].size()<<endl;
			for(int j = 0; j < data[i].size(); j++)
			{
				Info y = data[i][j];
				file<<y.info<<endl;
				for(int l = 0; l < 10; l++)
					file<<y.sign[l]<<" ";
				file<<endl;
			}
		}
	}
	void readfile(){
		ifstream fin("data.txt", ios::in);
		head.clear();
		tmp_data.clear();
		data.clear();
		user.clear();
		int n;
		fin>>n;
		for(int i = 0; i < n; i++)
		{
			header x;
			fin>>x.block_id>>x.nonce>>x.time>>x.userid>>x.level;
			fin>>x.info_hash;
			if(i != 0)fin>>x.prev_hash;
			int m;
			fin>>m;
			tmp_data.clear();
			for(int j = 0; j < m; j++){
				Info y;
				fin>>y.info;
				for(int l = 0; l < 10; l++)
					fin>>y.sign[l];
				y.decode_info();
				if(y.op == 1){
					User ny;
					ny.money = 0;
					ny.public_key = y.public_key;
					user.push_back(ny);
				}
				else if(y.op == 2){
					user[y.userid].money -= y.money;
					user[y.userid2].money += y.money;
				}
				tmp_data.push_back(y);
			}
			user[x.userid].money += 100;
			head.push_back(x);
			data.push_back(tmp_data);
		}
		tmp_data.clear();
		user_count = tmp_user_count = user.size();
	}
	bool check_block(int id){
		char info_test[41] = {'\0'};
		for(int i = 0; i < data[id].size(); i++){
			string tmp1(data[id][i].info);
			string tmp2(info_test);
			string tmp = tmp1+tmp2;
			for(int j = 0; j < 10; j++)
				tmp += to_string(data[id][i].sign[j]);
			hashs(tmp, info_test);
		}
		//cout<<info_test<<endl<<head[id].info_hash<<endl;
		for(int i = 0; i < 40; i++){
			if(info_test[i] != head[id].info_hash[i]) return false;
		}
		if(id == head.size()-1) return true;
		char test[41] = {'\0'};
		head[id].block_hash(test);
		for(int i = 0; i < 40; i++){
			if(test[i] != head[id+1].prev_hash[i]) return false;
		}
		return true;
	}
	void check_integrity(){
		bool ok = 1;
		for(int i = 0; i < head.size(); i++)
		{
			if(!check_block(i)){
				cout<<"Block: "<<i<<" is invalid"<<endl;
				ok = 0;
			}
		}
		if(ok){
			cout<<"All blocks and data are valid"<<endl;
		}
		else{
			cout<<"1 to clear the data"<<endl;
			cout<<"Other to exit"<<endl;
			int op;
			cin>>op;
			if(op == 1){
				head.clear();
				tmp_data.clear();
				data.clear();
				user.clear();
				init();
			}
			else return ;
		}
	}
}chain;

inline ll labs(ll x){
	return x < 0 ? -x : x;
}

int main(){
	cout<<"Reading file"<<endl;
	chain.readfile();
	cout<<"File readed"<<endl;
	if(chain.head.size() == 0){
		cout<<"No data readed, initialize the block chain"<<endl;
		chain.init();
	}
	cout<<"Checking integrity of the data"<<endl;
	chain.check_integrity();
	while(1) {
		cout<<"======================================================================"<<endl;
		cout<<endl;
		cout<<"---------------"<<endl;
		cout<<"| 1 to view    |"<<endl;
		cout<<"| 2 to operate |"<<endl;
		cout<<"| 3 to quit    |"<<endl;
		cout<<"---------------"<<endl;
		int op;
		cin>>op;
		while(op == 1) {
			int op2;
			cout<<endl;
			cout<<"    -----------------------------------------"<<endl;
			cout<<"    | 1 to search one block by block ID      |"<<endl;
			cout<<"    | 2 to search one block by UNIX time     |"<<endl;
			cout<<"    | 3 to see all the chain information     |"<<endl;
			cout<<"    | 4 to see the deals in transaction pool |"<<endl;
			cout<<"    | 5 to see the users' information        |"<<endl;
			cout<<"    | Other to return to parent menu         |"<<endl;
			cout<<"    -----------------------------------------"<<endl;
			cin>>op2;
			if(op2 == 1) {
				cout<<"Input the block ID (-1 to return to last menu): ";
				int block_id; cin>>block_id;
				if(block_id == -1) continue;
				chain.display(block_id);
			}
			else if(op2 == 2) {
				cout<<"Input the time (-1 to return to last menu): ";
				int time; cin>>time;
				if(time == -1) continue;
				ll mxtime = INT_MAX, block_id = -1;
				for(int i = 0; i < chain.data.size(); i++){
					if(mxtime > labs(chain.head[i].time - time)){
						block_id = i;
						mxtime = labs(chain.head[i].time - time);
					}
					else break;
				}
				chain.display(block_id);
			}
			else if(op2 == 3){
				for(int i = 0; i < chain.data.size(); i++)
					chain.display(i);
			}
			else if(op2 == 4){
				for(int i = 0; i < chain.tmp_data.size(); i++){
					chain.tmp_data[i].display();
				}
			}
			else if(op2 == 5){
				for(int i = 0; i < chain.user.size(); i++){
					cout<<"User: "<<i<<endl;
					chain.user[i].display();
				}
			}
			else break;
		}
		while(op == 2) {
			cout<<endl;
			cout<<"    ---------------------------------"<<endl;
			cout<<"    | 1 to add a new user            |"<<endl;
			cout<<"    | 2 to make a transfer           |"<<endl;
			cout<<"    | 3 to add a new block           |"<<endl;
			cout<<"    | 4 to check integrity of data   |"<<endl;
			cout<<"    | Other to return to parent menu |"<<endl;
			cout<<"    ---------------------------------"<<endl;
			int op2;
			cin>>op2;
			if(op2 == 1) {
				chain.add_user(time(0));
			}
			else if(op2 == 2) {
				int from_id, to_id, money;
				cout<<"From user: ";
				cin>>from_id;
				cout<<"To user: ";
				cin>>to_id;
				cout<<"Transfer: ";
				cin>>money;
				if(from_id >= chain.user_count || to_id >= chain.user_count || from_id < 0 || to_id < 0){
					cout<<"Invalid user ID, user may not been confirmed or may not exist"<<endl;
					continue;
				}
				if(money < 0){
					cout<<"Invalid transfer amount, you can only transfer nonnegative amount of coins to other"<<endl;
					continue;
				}
				chain.make_transfer(time(0), from_id, to_id, money);
			}
			else if(op2 == 3) {
				int user_id;
				cout<<"User: ";
				cin>>user_id;
				if(user_id >= chain.tmp_user_count || user_id < 0){
					cout<<"Invalid user ID, user may not been confirmed or may not exist"<<endl;
					continue;
				}
				chain.add_block(time(0), user_id);
			}
			else if(op2 == 4) {
				chain.check_integrity();
			}
			else break;
		}
		if(op == 3) break;
		cout<<"======================================================================"<<endl<<endl;
	}
	chain.writefile();
	return 0;
}