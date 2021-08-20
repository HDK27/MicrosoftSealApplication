#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>


using namespace std::chrono;
using namespace seal;
using namespace std;


void banner(){
		cout<<"          ******************************************"<<endl;
        cout<<"          *                                        *"<<endl;
        cout<<"          *         Genetic Disease Deparment      *"<<endl;
        cout<<"          *                                        *"<<endl;
        cout<<"          ******************************************"<<endl<<endl;
}

void pause(){
	cin.get();
	do {
     		cout << '\n' << "Press the Enter key to continue.";
   	} while (cin.get() != '\n');
}



string retrievealpha(int index, string filename){
	ifstream in;
	//system("pwd");
	string alphalocation="Cloud/"+filename+"/alpha.txt";
	in.open(alphalocation);
	string temp;	
	for (int i=0; i<=index; i++){
		getline(in, temp);
		}
	system(("echo "+temp+ " | openssl enc -aes-256-cbc -d -a -iter 1000 -pass pass:\"pass\" >temp.txt").c_str());
	in.close();
	in.open("temp.txt");
	in>>temp;
	in.close();
	system("rm temp.txt");
	return temp;
}

void saveCiphertext(Ciphertext encrypted, string filename){
	ofstream ct;
	ct.open(filename, ios::binary);
	encrypted.save(ct);
}


Ciphertext loadCiphertext(string filename, EncryptionParameters parms){

	SEALContext context(parms);
	  
	ifstream ct;
	ct.open(filename, ios::binary);
	Ciphertext result;
	result.load(context, ct);

	return result;
}


void saveSecretKey(SecretKey sk, string filename){
	ofstream ct;
	ct.open(filename, ios::binary);
	sk.save(ct);
}


SecretKey loadSecretKey(string filename, EncryptionParameters parms){

  	SEALContext context(parms);
  
  	ifstream ct (filename);
  	if (ct.is_open()){
  	SecretKey result;
  	result.load(context, ct);
  
  	return result;}

}

void savePublicKey(PublicKey pk, string filename){
	ofstream ct;
	ct.open(filename, ios::binary);
	pk.save(ct);
}


PublicKey loadPublicKey(string filename, EncryptionParameters parms){

	SEALContext context(parms);
	  
	ifstream ct (filename);
	if (ct.is_open()){
	PublicKey result;
	result.load(context, ct);
	  
	return result;}
}

bool exists(const char *fileName){
    ifstream infile(fileName);
    return infile.good();
}

int convert (char z){
	if(z=='A') return 4;
	if (z=='T') return 5;
	if (z=='G') return 6;
	if (z=='C') return 7;
}

bool snpEncode(string filename, vector<int64_t> &d, vector<int64_t> &alpha){
	ifstream infile(filename);
	if(infile.is_open()){
		string s,b;
		int chr,pos;
		char ref,alt;
		getline(infile,s);
		while(!infile.eof()){
			infile>>b>>chr>>pos>>ref>>alt;
			d.push_back(-(chr+24*pos));
			alpha.push_back(2048*convert(ref)+convert(alt));
			}
		infile.close();
		return true;
		}
	else
		cout<<"file not found"<<endl;
		return false;		
}

bool sendtocloud(string filename, EncryptionParameters parms, PublicKey pk){
	vector<int64_t> d;
	vector<int64_t> alpha;
	bool test=snpEncode("Client/Users/"+filename, d, alpha);
	if (test){
		SEALContext context(parms);
		Encryptor encryptor(context, pk);
		BatchEncoder encoder(context);
		Plaintext pt;
		encoder.encode(d,pt);
		Ciphertext ct;
		encryptor.encrypt(pt,ct);
		system(("mkdir Cloud/"+filename).c_str());
		string dsavelocation= "Cloud/"+filename+"/d.txt";
		string alphasavelocation= "Cloud/"+filename+"/alpha.txt";		
		saveCiphertext(ct, dsavelocation);
		for(int i=0; i<alpha.size(); i++){
			system(("echo \""+ to_string(alpha[i])+ "\" | openssl enc -aes-256-cbc  -a -iter 1000 -pass pass:\"pass\" >> "+alphasavelocation).c_str());
			//system("clear");
			}
		ofstream out;
		out.open("Client/db", ios_base::app);
		out<<filename<<endl;
		out.close();
		return true;
		}
	else return false;
}

Ciphertext retrievefromcloud(int64_t d1, EncryptionParameters parms, PublicKey pk, string filename){
	SEALContext context(parms);
	Encryptor encryptor(context, pk);
	BatchEncoder encoder(context);
	Evaluator evaluator(context);
	vector<int64_t> d;
	for (int i=0; i<5; i++){d.push_back(d1);}
	Plaintext pt;
	encoder.encode(d,pt);
	Ciphertext ct,ct1,ct2;
	encryptor.encrypt(pt,ct1);
	string dsavelocation= "Cloud/"+filename+"/d.txt";
	ct2=loadCiphertext(dsavelocation, parms);
	evaluator.add(ct1,ct2,ct);
	return ct;
}

int findindex(Ciphertext ct, EncryptionParameters parms, SecretKey sk){
	SEALContext context(parms);
	Evaluator evaluator(context);
	BatchEncoder encoder(context);
        Decryptor decryptor(context, sk);
	Plaintext pt;
	decryptor.decrypt(ct, pt);
  	vector<int64_t> d;
  	encoder.decode(pt, d);
	for(int i=0; i<5; i++)
		if(d[i]==0) return i;
		return -1;

}

bool userexists(string filename){
	ifstream in("Client/db");
	string user;
	while(!in.eof()){
	in>>user; 
	if(user==filename) return true;}
	return false;
}


int main(){
	//setting BFV parameters
	
	system("clear");
	cout << "Setting encryption parameters";
    
    	EncryptionParameters parms(scheme_type::bfv);
    	parms.set_poly_modulus_degree(2048);
    	parms.set_coeff_modulus(CoeffModulus::BFVDefault(2048));
    	parms.set_plain_modulus(PlainModulus::Batching(2048, 30));
    	SEALContext context(parms);	
	

    	cout<< " ...... Done." << endl;

	//generating Keys, Encryptor and Decryptor
    	cout << "Generating public,private keys";

    	KeyGenerator keygen(context);
        
	PublicKey pk;
	if(exists("Client/Keys/PublicKey"))	pk=loadPublicKey("Client/Keys/PublicKey",parms);
	else {keygen.create_public_key(pk);	savePublicKey(pk,"Client/Keys/PublicKey");}

    	SecretKey sk;
	if(exists("Client/Keys/SecretKey"))	sk=loadSecretKey("Client/Keys/SecretKey",parms);
	else {sk=keygen.secret_key();	saveSecretKey(sk,"Client/Keys/SecretKey");}
	
	cout<< " ...... Done."<<endl;
	

	bool file;
	string filename;
	string alphai;
	string alpha1;
	int index;
	Ciphertext ct;
	if(!exists("Client/db")) system("touch Client/db");
	//start of code
	
	char choice='0';
	while(true){
		
		switch (choice){

			case '0':
				system("clear");
				banner();
				cout<<"Welcome, what would you like to do?"<<endl
					<<"(1) To input user data to cloud"<<endl
					<<"(2) To check user data"<<endl
					<<"(q) To exit"<<endl;
 				cin>>choice;
				break;

			case '1':
				system("clear");
				banner();
				cout<<"Enter Patient Filename: "<<endl;
				cin>>filename;
				if(userexists(filename)) {cout<<"User already exists!"<<endl; choice='1';}
					else{
					file=sendtocloud(filename, parms, pk);//happening on the server and saving on the cloud
					if (file) {cout<<"Done."<<endl; choice='0';}
					else choice='0';
					}
				pause();
			    	break;
			case '2':
				system("clear");
				banner();
				cout<<"Input user Filename:"<<endl;
				cin>>filename;
				if(userexists(filename)){
					cout<<"Input value d':"<<endl;
					int64_t d1;
					cin>>d1;
					ct=retrievefromcloud(d1, parms, pk, filename);//happening on the cloud
					cout<<"Input value alpha':"<<endl;
					cin>>alpha1;
					index=findindex(ct, parms, sk);
					if(index>=0) {
						cout<<"Alpha at index: "<<index<<endl;
						alphai=retrievealpha(index, filename);
						if(stoi(alphai)==stoi(alpha1)) cout<<"No genertic desease"<<endl;
						else cout<<"Genetic desease found"<<endl;		
						}
					else cout<<"d' not found"<<endl;
					choice='0';
						}
				else{ cout<<"User doesn't exist!"<<endl; choice='0';}
				pause();
			    	break;
			case 'q': 
				cout<<"Thank you for coming!"<<endl;
				return 0;
			
			default: 
				choice='0';
		
			}
		}
}