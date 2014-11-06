/*Generate an RSA key p,q.  The RSA key is the secret information really...but can be generated once as long as it's globally strong enough not to be brute 
forced.

n=p*q.

http://www.hashcash.org/papers/time-lock.pdf

phi=(p-1)*(q-1).  Store phi.

compute 2^2^(t) by using Ph

Creates a random number K per request.  Each one is one time use.  Store K in a priority queue by timestamp as well.

on ANY lookup Kt, pop K values off the queue until the timestamp delay is met (all expireds).  Remove all expireds from the set.

If Kt was in the expireds, return "EXPIRED" after completion

otherwise, check if Kt was in the key set.  If Kt is in the key set, remove Kt from the key set, and return "VALID"

otherwise, return "INVALID"


on a request, generate K securely, insert K into keyset and insert K into priority queue.    Keyset could be a really good hash table implementation too.

Compute Ck=K+2^2^t mod n
send n and Ck and t.  with a javascript redirect.   If 
*/

class timelock_ddos
{
private:
	struct timestamped_requestkey
	{
		ssl::bigint key;
		time_t timestamp;
		bool operator<(const timestamped_requestkey& other)
		{
			return timestamp > other.timestamp; //smallest timestamp goes on the top
		}
	};
	std::priority_queue<timestamped_requestkey> requestqueue;
	std::unordered_set<ssl_bigint> valid_requestkeys;
	#ifdef THREAD_SUPPORT
	std::mutex datamutex;
	#endif
	
	size_t ksize;
	timedelta_t timedelay;
	uint32_t tparam;

	void locked_insert(const timestamped_requestkey& trk)
	{
		#ifdef THREAD_SUPPORT
		std::lock_guard<std::mutex> lock(datamutex);
		#endif
		requestqueue.insert(trk);
		valid_requestkeys.insert(trk.key);
	}
public:
	enum keycheck_result_t
	{
		
		VALID=1,
		INVALID_EXPIRED,
		INVALID_NOTFOUND
	};
	struct generate_result_t
	{
		string Ck;
		string modulus;
		uint32_t timelock;
	};
	timelock_ddos(uint32_t timeparameter,const size_t& private_key_length=2048,timedelta_t td=timedelta_t(10000),size_t Ksize=0):ksize(Ksize ? Ksize : private_key.modulus_bitwidth)
		modulus(private_key.modulus),phi(private_key.phi),tparam(timeparameter)
	{}
	
	
	generate_result_t generate()
	{
		timestamped_requestkey trk((ssl::securerandom(ksize)),time());
		
		ssl::bigint p=generatePrime(ksize/2),q=generatePrime(ksize/2);
		ssl::bigint modulus=p*q;
		ssl::bigint euler=modulus-p-q+1; //(p-1)*(q-1);
		
		ssl::bigint Ck=(trk.key+ssl::pow(2, ssl::pow(2, tparam, euler), modulus)) % modulus;
		return {Ck.tohexstring(),modulus.tohexstring(),tparam};
	}
	keycheck_result_t keycheck_result(std::string keystr)
	{
		#ifdef THREAD_SUPPORT
		std::lock_guard<std::mutex> lock(datamutex);
		#endif
	
		ssl::bigint k=ssl::bigint::fromb32string(keystr);
		time_t current=time();
		time_t cutoff=current-timedelay;
		keycheck_result_t result=VALID;
		for(bigint ktest=requestqueue.top();(ktest=requestqueue.top()).timestamp < cutoff;requestqueue.pop())
		{
			valid_requestkeys.remove(ktest.key);
			if(ktest.key==k)
			{
				result=INVALID_EXPIRED;
			}
		}
		return valid_requestkeys.erase(k) ? result : INVALID_NOTFOUND;
	}
}

//An input filter that passes a request lacking the relevant cookie to a ddos delay html GET instead with the request redirect embedded.  Should be stupid fast (like a static page) preconfigured with the relevant public parameters


