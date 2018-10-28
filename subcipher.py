import re
from random import sample
from sigdict import SIGDICT

test = """
"vabb, wkcuna, rx zauxq qug bfnnq qka uxv sfro jqlcbm aroqoar xj oya                                
pfxuqwqkoar. pfo c vqku mxf, cj mxf gxuo oabb la oyqo oycr laqur vqk,                               
cj mxf rocbb okm ox gajaug oya cujqlcar qug yxkkxkr wakwaokqoag pm oyqo                             
quocnykcro-c kaqbbm pabcaha ya cr quocnykcro-c vcbb yqha uxoycuz                                    
lxka ox gx vcoy mxf qug mxf qka ux bxuzak lm jkcaug, ux bxuzak lm                                   
'jqcoyjfb rbqha,' qr mxf nqbb mxfkrabj! pfo yxv gx mxf gx? c raa c                                  
yqha jkczyoauag mxf-rco gxvu qug oabb la qbb oya uavr."                                             
                                                                                                    
co vqr cu sfbm, 1805, qug oya rwaqtak vqr oya vabb-tuxvu quuq wqhbxhuq                              
rnyakak, lqcg xj yxuxk qug jqhxkcoa xj oya alwkarr lqkmq jagxkxhuq.                                 
vcoy oyara vxkgr rya zkaaoag wkcuna hqrcbc tfkqzcu, q lqu xj yczy                                   
kqut qug clwxkoquna, vyx vqr oya jckro ox qkkcha qo yak kanawocxu. quuq                             
whbxhuq yqg yqg q nxfzy jxk rxla gqmr. rya vqr, qr rya rqcg, rfjjakcuz                              
jkxl bq zkcwwa; zkcwwa pacuz oyau q uav vxkg cu ro. waoakrpfkz, frag                                
xubm pm oya abcoa.                                                                                  
                                                                                                    
qbb yak cuhcoqocxur vcoyxfo aenawocxu, vkcooau cu jkauny, qug gabchakag                             
pm q rnqkbao-bchakcag jxxolqu oyqo lxkucuz, kqu qr jxbbxvr:                                         
                                                                                                    
"cj mxf yqha uxoycuz paooak ox gx, nxfuo (xk wkcuna), qug cj oya                                    
wkxrwano xj rwaugcuz qu ahaucuz vcoy q wxxk cuhqbcg cr uxo oxx oakkcpba,                            
c ryqbb pa hakm nyqklag ox raa mxf oxuczyo paovaau 7 qug 10 quuaooa                                 
rnyakak."                                                                                           
                                                                                                    
"yaqhaur! vyqo q hckfbauo qooqnt!" kawbcag oya wkcuna, uxo cu oya                                   
baqro gcrnxunakoag pm oycr kanawocxu. ya yqg sfro auoakag, vaqkcuz qu                               
alpkxcgakag nxfko fucjxkl, tuaa pkaanyar, qug ryxar, qug yqg roqkr xu                               
ycr pkaqro qug q rakaua aewkarrcxu xu ycr jbqo jqna. ya rwxta cu oyqo                               
kajcuag jkauny cu vycny xfk zkqugjqoyakr uxo xubm rwxta pfo oyxfzyo, qug                            
vcoy oya zauoba, wqokxucdcuz cuoxuqocxu uqofkqb ox q lqu xj clwxkoquna                              
vyx yqg zkxvu xbg cu rxncaom qug qo nxfko. ya vauo fw ox quuq whbxhuq,                              
tcrrag yak yqug, wkarauocuz ox yak ycr pqbg, rnauoag, qug rycucuz yaqg,                             
qug nxlwbqnauobm raqoag yclrabj xu oya rxjq.                                                        
                                                                                                    
"jckro xj qbb, gaqk jkcaug, oabb la yxv mxf qka. rao mxfk jkcaug'r                                  
lcug qo karo," rqcg ya vcoyxfo qboakcuz ycr oxua, pauaqoy oya                                       
wxbcoauarr qug qjjanoag rmlwqoym xj vycny cugcjjakauna qug ahau ckxum                               
nxfbg pa gcrnakuag."""


def allsigs(filename):
    sigdict = {}
    rawwords = open(filename).read().splitlines()
    words = [''.join(re.findall(r'[a-z]+', word.lower())) for word in rawwords]
    words = sorted(list(set(words)), key=lambda x: len(x))
    sigs = [sig(word) for word in words]
    for i in range(len(words)):
        try:
            sigdict[sigs[i]].append(words[i])
        except KeyError:
            sigdict[sigs[i]] = [words[i]]
    return sigdict


def sig(word):
    letterset = set()
    letterset_add = letterset.add
    letters_in_order = [c for c in word if not (c in letterset or letterset_add(c))]
    letter_to_number = dict(zip(letters_in_order, list(range(len(letters_in_order)))))
    return ''.join([chr(letter_to_number[c]+97) for c in word])


def bulksig(phrase):
    wordlist = [len(word) for word in phrase.split(' ')]
    total_sig = sig(''.join(phrase.split(' ')))
    return [total_sig[sum(wordlist[:i]):sum(wordlist[:i+1])] for i in range(len(wordlist))]


def encode(plaintext, letters='abcdefghijklmnopqrstuvwxyz'):
    radix = dict(zip(list(letters), sample(list(letters), k=26)))
    #radix = dict(zip(list(letters), list(letters)))
    radix = {**radix, **dict([[k.upper(), v.upper()] for k, v in radix.items()])}
    return ''.join([radix[c] if c in radix.keys() else c for c in plaintext])


def decode(ciphertext, letters='abcdefghijklmnopqrstuvwxyz'):
    global SIGDICT

    #### Stage 1 - Preparation ####

    # Sanitizing the input
    cip_words = ''.join(re.findall(r'[{} ]+'.format(letters), ciphertext.lower())).split(' ')

    # Removing duplicates of words
    cip_words_unique = list(set(cip_words))

    # Creating a list of words and their signatures
    word_sigs_unsort = [[cip_words_unique[i], sig(cip_words_unique[i])] for i in range(len(cip_words_unique)) if sig(cip_words_unique[i]) in SIGDICT.keys()]

    # Sorting previous list by length of signature list
    word_sigs = sorted(word_sigs_unsort, key=lambda s: len(SIGDICT[s[1]]))

    # Unzipping the two lists
    words_sort, sigs_sort = zip(*word_sigs)

    # Number of letters that exist in the ciphertext
    target_letternum = len(set(list(''.join(cip_words_unique))))

    # Variable initialization
    unver_groups = [[]]
    groups = []
    radix_groups = []
    target_words = []

    #### Stage 2 - Finding Pangrams ####

    # Iterating through each word in the encoded text until all letters are found
    for i in range(len(sigs_sort)):

        # Appending the next word to be evaluated
        target_words.append(words_sort[i])

        # Storing all previously solved letters
        temp_radix = ''.join(target_words[:-1])

        # Making sure the appended word is not redundant
        if all([c in temp_radix for c in target_words[-1]]):

            # If it is redundant, forget it and skip to the next one
            target_words = target_words[:-1]
            continue

        # Creating the target bulk signature
        target_sig = bulksig(' '.join(target_words))

        # Expanding on the previously existing groups so that they are ready to verify
        unver_groups = [group+[member] for group in (groups or unver_groups) for member in SIGDICT[sigs_sort[i]]]

        # Forming a list of temporary verified groups
        temp_groups = [ugroup for ugroup in unver_groups if bulksig(' '.join(ugroup)) == target_sig]

        # Making sure that the list of temporary groups is not empty
        if not temp_groups:

            # If it is, forget the prevoius word and skip to the nextone
            target_words = target_words[:-1]
            continue

        # If it isn't empty, make those groups permanent
        groups = temp_groups[:]

        # Iterating through the verified groups
        for group in groups:

            # If any of the groups cover all existing letters
            if len(set(list(''.join(group)))) == target_letternum:

                # Add that group to the list of groups that are ready for stage 3
                radix_groups.append(group)

        # Breaking out of the loop if ready for stage 3
        if radix_groups:
            break

    # If all words are iterated through without finding a radix group
    else:
        return 'Decoding failed!'

    # More variable initialization
    error_ratios = []
    radices = []

    #### Stage 3 - Minimizing Error ####

    # Finding which radices generate the least error
    for rgroup in radix_groups:

        # Building the pangrams for the radix
        pln_pangram = list(''.join(rgroup))
        cip_pangram = list(''.join(target_words))

        # Clearing the radix dictionary
        radix = {}

        # Building the radix
        for pln, cip in list(zip(pln_pangram, cip_pangram)):
            radix[cip] = pln

        # Adding it to the list of radices 
        radices.append(radix)

        # Getting the error ratio for the radix
        pln_words = ''.join([radix[c] if c in radix.keys() else c for c in ' '.join(cip_words)]).split(' ')
        error = [p in SIGDICT[sig(p)] for p in pln_words if sig(p) in SIGDICT.keys()]

        # Adding it to the list of error ratios
        error_ratios.append(len([e for e in error if e])/len(error))

    # Selecting the least error-prone radix
    radix = radices[error_ratios.index(max(*error_ratios) if len(error_ratios) > 1 else error_ratios[0])]

    # Extending the radix for use to decrypt the whole ciphertext
    radix = {**radix, **dict([[k.upper(), v.upper()] for k, v in radix.items()])}

    # Returning the decrypted ciphertext
    return ''.join([radix[c] if c in radix.keys() else c for c in ciphertext])

#open('sigdict.py', 'w').write('SIGDICT = '+str(allsigs('words.txt')))
#print(decode(test))
