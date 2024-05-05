import json
import hashlib
import string
import random
import datetime
from app1.models import property

def get_hash(block):
    str_block = json.dumps(block, sort_keys=True)
    str_block = str_block.encode()
    return hashlib.sha256(str_block).hexdigest()

class block_chain:
    def __init__(self, _data=None):
        if _data == None:
            self.data = {"chain": [],
                        "latest_index": -1,
                        "no_entries":0,
                        }
        else:
            self.data = _data        
    
    def add_block(self, prop, type_change):
        genesis_string = ""
        if self.data["latest_index"] == -1:
            genesis_string = ''.join(random.choices(string.ascii_lowercase+string.digits, k=20))
            genesis_hash = hashlib.sha256(genesis_string.encode()).hexdigest()
            prev_hash = genesis_hash
        else:
            prev_hash = get_hash(self.data["chain"][self.data["latest_index"]])
        new_block = {"index": self.data["latest_index"]+1,
                     "prev_hash": prev_hash,
                     "date_created": str(datetime.datetime.now()),
                     "type_change": type_change,
                     "prop_id": prop.id,
                     "sellor_lessor": prop.sellor_lessor.id,
                     "contract_type": prop.contract_type, 
                     "prop_type": prop.prop_type,
                     "price": prop.price,
                     "location": prop.location,
                     "close_metro": prop.close_metro,
                     "close_NH": prop.close_NH, 
                     "cose_ap": prop.close_ap,
                     "date_avail": str(prop.date_avail)}
        self.data["chain"].append(new_block)
        self.data["latest_index"] += 1
        self.data["no_entries"] += 1
        return genesis_string
    
    def Verify_BlockChain(self, genesis_str):
        if self.data["no_entries"] != len(self.data["chain"]):
            return False, -2
        genesis_hash = hashlib.sha256(genesis_str.encode()).hexdigest()
        if genesis_hash != self.data["chain"][0]["prev_hash"]:
            return False, 0
        for i in range(1, self.data["no_entries"], 1):
            if self.data["chain"][i]["prev_hash"] != get_hash(self.data["chain"][i-1]):
                return False, (i-1)
        return True, -1
    
    def verify_curr_prop(self):
        curr_chain = self.data["chain"]
        curr_prop = {}
        for i in curr_chain:
            if i["type_change"] == "delete" or i["type_change"] == "bought":
                curr_prop.pop(i["prop_id"])
            else:
                curr_prop[i["prop_id"]] = i
        all_prop = property.objects.all()
        for prop in all_prop:
            curr_prop_bc = curr_prop[prop.id]
            if curr_prop_bc["sellor_lessor"] != prop.sellor_lessor.id:
                return False
            if curr_prop_bc["contract_type"] != prop.contract_type:
                return False
            if curr_prop_bc["prop_type"] != prop.prop_type:
                return False
            if curr_prop_bc["price"] != prop.price:
                return False
            if curr_prop_bc["location"] != prop.location:
                return False
            if curr_prop_bc["close_metro"] != prop.close_metro:
                return False
            if curr_prop_bc["close_NH"] != prop.close_NH:
                return False
            if curr_prop_bc["cose_ap"] != prop.close_ap:
                return False
            if curr_prop_bc["date_avail"] != str(prop.date_avail):
                return False
        return True
