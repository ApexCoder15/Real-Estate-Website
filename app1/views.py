from django.shortcuts import render, redirect
from django.http import Http404, HttpResponse, HttpResponseRedirect
from .forms import create_user_form, add_prop_form, upload_key
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from app1.models import property, MyUser, blockchain
from app1.signatures import *
from app1.one_time_passwd import *
from app1.BlockChain import *
import os
from django.conf import settings
import stripe
import requests
import json
import rsa

stripe.api_key = settings.STRIPE_SECRET_KEY
otp = ""

def signup(request):
    if request.method == 'POST':
        form = create_user_form(request.POST)
        if form.is_valid():
            user = form.save()
            raw_password = form.cleaned_data.get('password1')
            em = user.email
            user = authenticate(request, email=user.email, password=raw_password)
            if user is not None:
                #load(em)
                login(request, user)
            else:
                print("user is not authenticated")
            (pubkey, privkey) = rsa.newkeys(2048)
            priv_key_path = os.path.join("user_keys/"+ user.email + '_private_key.pem')
            with open(priv_key_path, 'wb') as pk:
                pk.write(privkey.save_pkcs1('PEM'))
            pub_key_path = os.path.join("user_keys/"+ user.email + '_public_key.pem')
            with open(pub_key_path, 'wb') as pk:
                pk.write(pubkey.save_pkcs1('PEM'))
            private_k_path = os.path.join("user_keys/" + 'main_private_key.pem')
            create_cert(user.email, private_k_path, pub_key_path)
            return redirect("/download_private")    
    else:
        form = create_user_form()
    return render(request, 'signup.html', {'form': form})  

@login_required
def initiate_payment(request, prop_id):  
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    amt = int(property.objects.filter(id =prop_id).values()[0]["price"])
    if request.method == 'POST':
        payment_intent = stripe.PaymentIntent.create(
            amount=int(property.objects.filter(id =prop_id).values()[0]["price"]),
            currency='inr',
            description='Payment Gateway'
        )
        client_secret = payment_intent.client_secret
        return buy_prop(request, prop_id)
    return render(request, "payment.html", {"key": settings.STRIPE_PUBLISHABLE_KEY, "prop_id1": prop_id, "amt": amt})

@login_required
def download_private_key(request):
    curr_user = request.user
    file_path = os.path.join("user_keys/"+ curr_user.email + '_private_key.pem')
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/x-pem-file")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404

@login_required
def download_contract(request, cont_name):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')  
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    curr_user = request.user
    prop_id, seller_id, buyer_id = get_ids(cont_name)
    if curr_user.id != seller_id and curr_user.id != buyer_id:
        if int(curr_user.user_type) != 2:
            return render(request, 'not_authorised.html')
    file_path = os.path.join("contracts/"+ cont_name)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/x-pem-file")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404

@login_required
def buy_prop(request, prop_id):  
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    buyer = request.user
    prop = property.objects.filter(id =prop_id).values()
    seller_id = prop[0]['sellor_lessor_id']
    seller = MyUser.objects.filter(id=seller_id).values()
    seller_email = seller[0]['email']
    file_name = "contracts/"+str(prop_id)+"_"+str(seller[0]['id'])+"_"+".pdf"
    new_file_name = "contracts/"+str(prop_id)+"_"+str(seller[0]['id'])+"_"+str(buyer.id)+".pdf"
    os.rename(file_name, new_file_name)
    sign_pdf("Buyer", new_file_name, get_cert_path(buyer.email), get_private_key_path(buyer.email))
    prop_todelete = property.objects.get(id = prop_id)
    curr_db_object = blockchain.objects.get()
    curr_bc = block_chain(curr_db_object.chain)
    curr_bc.add_block(prop_todelete, "bought")
    curr_db_object.chain = curr_bc.data
    curr_db_object.save()
    prop_todelete.delete()
    return render(request, 'buy_page.html')


@login_required
def add_prop(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if request.method == "POST":
        prop = property(sellor_lessor=request.user)
        form = add_prop_form(request.POST, instance=prop)
        if form.is_valid():
            form.save()
            prop_id = prop.id
            data_print = ""
            if prop.contract_type == "0":
                data_print += "Rent Contract\n"
            elif prop.contract_type == "1":
                data_print += "Property Transfer Contract\n"
            if blockchain.objects.count() == 0:
                curr_bc = block_chain()
                _genesis_str = curr_bc.add_block(prop, "add")
                bc_db = blockchain(genesis_str = _genesis_str, chain = curr_bc.data)
                bc_db.save()
            else:
                curr_db_object = blockchain.objects.get()
                curr_bc = block_chain(curr_db_object.chain)
                curr_bc.add_block(prop, "add")
                curr_db_object.chain = curr_bc.data
                curr_db_object.save()
            data_print = [data_print,]
            file_name = "contracts/"+str(prop_id)+"_"+str(request.user.id)+"_"+".pdf"
            create_pdf(data_print, file_name)
            sign_pdf("Seller", file_name, get_cert_path(request.user.email), get_private_key_path(request.user.email))
            return redirect(home_page)
    else:
        form = add_prop_form()
    return render(request, 'addprop.html', {'form': form})

@login_required
def prop_listing_buyer(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    all_prop = property.objects.all()
    return render(request, 'prop_listing.html', {"all_prop": all_prop})

@login_required
def user_delete(request, user_id):  
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(request.user.user_type) != 2:
        logout_view()
        return render(request, 'not_authorised.html')
    usr = MyUser.objects.get(id = user_id)
    usr.is_active = 0
    usr.save()
    return render(request, 'usr_deleted.html')

def get_ids(contract_name):
    buyer_id = ""
    seller_id = ""
    prop_id = ""
    c = 0
    for ch in contract_name:
        if ch == ".":
            break
        if ch == "_":
            c += 1
            continue
        if c == 0:
            prop_id += ch
        if c == 1:
            seller_id += ch
        if c == 2:
            buyer_id += ch
    return int(prop_id), int(seller_id), int(buyer_id)
        

@login_required
def contract_list(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    contracts = [f for f in os.listdir("contracts") if os.path.isfile(os.path.join("contracts", f))]
    cont_lst = []
    for cont in contracts:
        if cont[-5] == "_":
            continue
        prop_id, seller_id, buyer_id = get_ids(cont)
        seller = MyUser.objects.filter(id = seller_id).values()
        buyer = MyUser.objects.filter(id = buyer_id).values()
        if len(seller) == 0 or len(buyer) == 0:
            continue
        # if property is deleted prop will be empty.
        cont_lst.append((prop_id, seller[0]["name"], buyer[0]["name"], cont))
    return render(request, 'contract_list.html', {"data": cont_lst})

@login_required
def verify_prop_listing_db(request):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')  
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html') 
    curr_db_object = blockchain.objects.get()
    curr_bc = block_chain(curr_db_object.chain)
    stat = curr_bc.verify_curr_prop()
    if stat:
        return render(request, "db_verified.html")
    return render(request, 'db_notverified.html')

@login_required
def approve_agg(request, user_id):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(request.user.user_type) != 2:
        logout_view()
        return render(request, 'not_authorised.html')
    usr = MyUser.objects.get(id = user_id)
    usr.admin_auth = True
    usr.save()
    return redirect(agg_req_list)

@login_required
def agg_req_list(request):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(request.user.user_type) != 2:
        return HttpResponseRedirect("Not authorised")
    all_user = MyUser.objects.filter(is_active = 1).filter(user_type = "2").filter(admin_auth = False).values()
    return render(request, 'list_user_req.html', {"all_user": all_user})

@login_required
def report_user(request, prop_id):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    prop = property.objects.get(id =prop_id)
    prop.sellor_lessor.reported = True
    prop.sellor_lessor.save()
    return redirect(prop_listing_buyer)

@login_required
def remove_report(request, user_id):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(request.user.user_type) != 2:
        logout_view()
        return render(request, 'not_authorised.html')
    usr = MyUser.objects.get(id = user_id)
    usr.reported = False
    usr.save()
    return redirect(user_list)

@login_required
def verify_prop_listing(request):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html') 
    if blockchain.objects.count() == 0:
        bc_verified = True
    else:
        curr_db_object = blockchain.objects.get()
        curr_bc = block_chain(curr_db_object.chain)
        bc_verified, problem_index = curr_bc.Verify_BlockChain(curr_db_object.genesis_str)
        if not bc_verified:
            return render(request, 'bc_issue.html', {"issue_index": problem_index})
    return render(request, 'bc_ver_success.html')
    

@login_required
def verify_contract(request, contract_name):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html') 
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')   
    prop_id, seller_id, buyer_id = get_ids(contract_name)
    seller = MyUser.objects.filter(id = seller_id).values()
    buyer = MyUser.objects.filter(id = buyer_id).values()
    buyer_cert = "cert_keys/"+buyer[0]["email"]+"_certificate.pem"
    seller_cert = "cert_keys/"+seller[0]["email"]+"_certificate.pem"
    cont_path = "contracts/"+contract_name
    status = verify_pdf(buyer_cert, seller_cert, cont_path)
    if status:
        return render(request, "contract_ver_suss.html")
    else:
        return render(request, "contract_unverified.html")

@login_required
def curr_prop_list(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')  
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html') 
    curr_user = request.user
    all_property = property.objects.filter(sellor_lessor = curr_user).values()
    return render(request, 'list_curr_prop.html', {"all_property": all_property})

@login_required
def view_contract_buyer(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html') 
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')  
    contracts = [f for f in os.listdir("contracts") if os.path.isfile(os.path.join("contracts", f))]
    cont_lst = []
    for cont in contracts:
        if cont[-5] == "_":
            continue
        prop_id, seller_id, buyer_id = get_ids(cont)
        if buyer_id != request.user.id:
            continue
        seller = MyUser.objects.filter(id = seller_id).values()
        buyer = MyUser.objects.filter(id = buyer_id).values()
        if len(seller) == 0 or len(buyer) == 0:
            continue
        cont_lst.append((seller[0]["name"], buyer[0]["name"], cont))
    return render(request, 'contract_list_bs.html', {"data": cont_lst})

@login_required
def view_contract_seller(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    contracts = [f for f in os.listdir("contracts") if os.path.isfile(os.path.join("contracts", f))]
    cont_lst = []
    for cont in contracts:
        if cont[-5] == "_":
            continue
        prop_id, seller_id, buyer_id = get_ids(cont)
        if seller_id != request.user.id:
            continue
        prop = property.objects.filter(id = prop_id).values()
        seller = MyUser.objects.filter(id = seller_id).values()
        buyer = MyUser.objects.filter(id = buyer_id).values()
        if len(seller) == 0 or len(buyer) == 0:
            continue
        cont_lst.append((seller[0]["name"], buyer[0]["name"], cont))
    return render(request, 'contract_list_bs.html', {"data": cont_lst})

@login_required
def delete_curr_prop(request, prop_id):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    prop_todelete_object = property.objects.get(id = prop_id)
    if request.user.id != prop_todelete_object.sellor_lessor.id:
        logout_view()
        return render(request, 'not_authorised.html')
    prop_todelete = property.objects.filter(id = prop_id)
    curr_db_object = blockchain.objects.get()
    curr_bc = block_chain(curr_db_object.chain)
    curr_bc.add_block(prop_todelete_object, "delete")
    curr_db_object.chain = curr_bc.data
    curr_db_object.save()
    prop_todelete.delete()
    file_path = "contracts/"+str(prop_id)+"_"+str(request.user.id)+"_"+".pdf"
    os.remove(file_path)
    return redirect(curr_prop_list)

@login_required
def user_list(request):
    if request.user.user_type != "2" or request.user.admin_auth == False:
        return render(request, 'not_authorised.html')
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')   
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(request.user.user_type) != 2:
        return HttpResponseRedirect("Not authorised")
    all_user = MyUser.objects.exclude(user_type = "2").filter(is_active = 1).values()
    return render(request, 'list_user.html', {"all_user": all_user})
    
def logout_view(request):
    curr_user = request.user
    curr_user.is_verified = 0
    curr_user.save()
    file_path = os.path.join("user_keys/"+ curr_user.email + '_private_key.pem')
    if os.path.exists(file_path):
        os.remove(file_path)
    logout(request)
    return redirect("/")

@login_required
def otp_send_verif(request):
    global otp
    if request.method == "POST":
        rec_inp = request.POST['otp_field']
        if rec_inp == otp:
            curr_user = request.user
            curr_user.email_verified = True
            curr_user.save()
            return redirect("/home")
        else:
            return HttpResponseRedirect("Not verified")
    otp = send_otp(request.user.email)
    return render(request, 'verify_email.html')

@login_required
def otp_send_login(request):
    global otp
    if request.method == "POST":
        rec_inp = request.POST['otp_field']
        if rec_inp == otp:
            curr_user = request.user
            curr_user.is_verified = 1
            curr_user.save()
            return redirect("/home")
        else:
            return HttpResponseRedirect("Not verified")
    otp = send_otp(request.user.email)
    return render(request, 'otp_login.html')

@login_required
def verify_user(request):
    if request.method == "POST":    
        curr_user = request.user
        file_path = os.path.join("user_keys/"+ curr_user.email + '_public_key.pem')
        if os.path.exists(file_path):
            form = upload_key(request.POST, request.FILES)
            #if request.FILES["file"].multiple_chunks:
                #logout_view(request)
                #return render(request, 'user_not_found.html')
            priv_key = (request.FILES["file"]).read()
            priv_key_path = os.path.join("user_keys/"+ str(request.FILES["file"]))
            with open(priv_key_path, 'wb') as pk:
                pk.write(priv_key)
            priv_key = rsa.PrivateKey.load_pkcs1(priv_key)
            with open(file_path, mode='rb') as privatefile:
                keydata = privatefile.read()
            pub_key = rsa.PublicKey.load_pkcs1(keydata)
            try:
                message = 'Go left at the blue tree'.encode()
                signature = rsa.sign(message, priv_key, 'SHA-1')
                if rsa.verify(message, signature, pub_key) == 'SHA-1':
                    curr_user.is_verified = 1
                    curr_user.save()
                    return redirect("/home")
            except rsa.pkcs1.VerificationError:
                return render(request, 'user_not_found.html')
        else:
            logout_view(request)
            return render(request, 'user_not_found.html')
    else:
        form = upload_key()
    return render(request, "verify_key.html", {"form": form})    

@login_required
def home_page(request):
    if request.user.is_verified == 0:
        return render(request, 'not_verified.html')        
    curr_user_type = request.user.user_type
    curr_user = request.user
    file_path = os.path.join("user_keys/"+ curr_user.email + '_private_key.pem')
    if request.user.email_verified == 0:
        return render(request, 'verify_email.html')
    if int(curr_user_type) == 0:
        if request.user.is_verified == 0:
            return render(request, 'not_verified.html')
        return render(request, 'home_sellers.html')
    elif int(curr_user_type) == 1:
        if request.user.is_verified == 0:
            return render(request, 'not_verified.html')        
        return render(request, 'home_buyers.html')
    elif int(curr_user_type) == 2:
        if request.user.user_type != "2" or request.user.admin_auth == False:
            return render(request, 'not_authorised.html')
        if request.user.is_verified == 0:
            return render(request, 'not_verified.html')        
        return render(request, 'aggregator_home.html')
    return HttpResponseRedirect("Error in User type.")

def ekyc_verf(request):
    if request.method == "POST":
        email = request.POST['email_']
        passwd = request.POST["passwd_"]
        data = {"email": email, "password": passwd}
        url = "https://192.168.3.39:5000/kyc"
        json_data = json.dumps(data)
        header = {"Content-Type": "application/json"}
        response = requests.post(url, data=json_data, headers=header, verify=False)
        if(response.text[12:28] == "Login successful" and response.text[40:-3] == "success"):
            return redirect("/login")
    return render(request, 'ekyc_verf.html')