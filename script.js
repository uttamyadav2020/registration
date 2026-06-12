document.addEventListener('DOMContentLoaded',()=>{
  const form=document.getElementById('regForm');
  const role=document.getElementById('role');
  const orgFields=document.getElementById('orgFields');
  const previewBtn=document.getElementById('preview');
  const previewPane=document.getElementById('previewPane');
  const previewJson=document.getElementById('previewJson');
  const message=document.getElementById('message');
  const pw=document.getElementById('password');
  const confirm=document.getElementById('confirm');
  const togglePwd=document.getElementById('togglePassword');
  const pwBar=document.getElementById('pwBar');
  const pwText=document.getElementById('pwText');

  function showMessage(text,type='success'){
    message.textContent=text;message.className='panel';
    message.classList.add(type==='success'?'success':'error');message.classList.remove('hidden');
    setTimeout(()=>message.classList.add('hidden'),3500);
  }

  function setInlineError(id,msg){
    const el=document.getElementById(id+"Error");
    if(!el) return;
    el.textContent=msg||'';
  }

  role.addEventListener('change',()=>{
    orgFields.classList.toggle('hidden',role.value!=='organizer');
  });

  // live validation
  form.first.addEventListener('input',()=> setInlineError('first', form.first.value.trim().length<2? 'First name must be at least 2 characters':''));
  form.last.addEventListener('input',()=> setInlineError('last', form.last.value.trim().length<2? 'Last name must be at least 2 characters':''));
  form.email.addEventListener('input',()=> setInlineError('email',!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.email.value)? 'Enter a valid email':''));

  // password show/hide
  if(togglePwd){
    togglePwd.addEventListener('click', ()=>{
      const t = pw.type === 'password' ? 'text' : 'password';
      pw.type = t; togglePwd.textContent = t==='password' ? 'Show' : 'Hide';
    });
  }

  // password strength
  function strengthScore(s){
    let score=0;
    if(!s) return 0;
    if(s.length>=8) score++;
    if(s.length>=12) score++;
    if(/[A-Z]/.test(s) && /[a-z]/.test(s)) score++;
    if(/\d/.test(s) || /[^A-Za-z0-9]/.test(s)) score++;
    return Math.min(score,4);
  }

  function updatePwMeter(){
    const v = pw.value||'';
    const score = strengthScore(v);
    const pct = (score/4)*100;
    if(pwBar) pwBar.style.setProperty('--pct', pct+'%');
    // set visual width via pseudo-element using inline style on element
    if(pwBar) pwBar.style.setProperty('--w', pct+'%');
    // fallback: set background-size by injecting style to ::after via width using transform
    if(pwBar){
      pwBar.style.position='relative';
      let inner = pwBar.querySelector('.pw-fill');
      if(!inner){ inner = document.createElement('div'); inner.className='pw-fill'; inner.style.position='absolute'; inner.style.left='0'; inner.style.top='0'; inner.style.height='100%'; inner.style.width=pct+'%'; inner.style.background='linear-gradient(90deg,#6ee7b7,#60a5fa)'; inner.style.transition='width .18s ease'; pwBar.appendChild(inner);
      } else { inner.style.width = pct+'%'; }
    }
    if(pwText){
      const labels = ['Very weak','Weak','Okay','Good','Strong'];
      pwText.textContent = labels[score];
    }
  }

  // --- Security helpers ---
  const commonPasswords = ['123456','password','123456789','qwerty','12345678','111111','1234567','sunshine','iloveyou','princess'];

  function meetsPolicy(p){
    if(!p) return false;
    if(p.length < 8) return false;
    if(!/[A-Z]/.test(p)) return false;
    if(!/[a-z]/.test(p)) return false;
    if(!/\d/.test(p)) return false;
    if(!/[^A-Za-z0-9]/.test(p)) return false;
    if(commonPasswords.includes(p)) return false;
    return true;
  }

  function canAttemptSubmit(){
    const key = 'submitAttempts';
    const raw = sessionStorage.getItem(key);
    const now = Date.now();
    let arr = raw ? JSON.parse(raw) : [];
    arr = arr.filter(ts => now - ts < 60000);
    if(arr.length >= 5) { sessionStorage.setItem(key, JSON.stringify(arr)); return false; }
    arr.push(now); sessionStorage.setItem(key, JSON.stringify(arr)); return true;
  }

  async function sha256Hex(text){
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  function randomSalt(len=16){
    const a = new Uint8Array(len); crypto.getRandomValues(a); return Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  async function pbkdf2Hex(password, salt, iterations=100000){
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits({name:'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-256'}, key, 256);
    return Array.from(new Uint8Array(derived)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  if(pw){
    pw.addEventListener('input', ()=>{
      updatePwMeter();
      setInlineError('password', pw.value.length<6 ? 'Password must be at least 6 characters':'' );
    });
    updatePwMeter();
  }

  if(confirm){
    confirm.addEventListener('input', ()=>{
      setInlineError('confirm', confirm.value !== pw.value ? 'Passwords do not match':'' );
    });
  }

  previewBtn.addEventListener('click',()=>{
    const data=collectForm();previewJson.textContent=JSON.stringify(data,null,2);
    previewPane.classList.toggle('hidden',false);
  });

  form.addEventListener('submit',(e)=>{
    e.preventDefault();
    const data=collectForm();
    const err=validate(data);
    if(err){
      if(err.includes('First')) setInlineError('first', err);
      if(err.includes('Last')) setInlineError('last', err);
      if(err.includes('email')||err.toLowerCase().includes('email')) setInlineError('email', err);
      if(err.toLowerCase().includes('password')) setInlineError('password', err);
      if(err.toLowerCase().includes('terms')) setInlineError('terms', err);
      showMessage(err,'error');
      return;
    }

    if(!canAttemptSubmit()){
      showMessage('Too many attempts — wait a moment and try again.','error');
      return;
    }

    if(!meetsPolicy(data.password)){
      setInlineError('password','Password must be 8+ chars, include upper/lower, digit and symbol, and not be a common password');
      showMessage('Choose a stronger password','error');
      return;
    }

    (async ()=>{
      try{
        const emailNorm = data.email.trim().toLowerCase();
        const emailHash = await sha256Hex(emailNorm);
        const salt = randomSalt(12);
        const pwdHash = await pbkdf2Hex(data.password, salt, 120000);
        const safe = {first:data.first,last:data.last,email:data.email,emailHash,role:data.role,org:data.org,created:new Date().toISOString(),pwdSalt:salt,pwdHash};
        saveRegistration(safe);
        showMessage('Registration saved securely (demo)');
        form.reset();orgFields.classList.add('hidden');previewPane.classList.add('hidden');
        ['first','last','email','password','confirm','org','terms'].forEach(id=>setInlineError(id,''));
        updatePwMeter();
      }catch(ex){console.error(ex);showMessage('Error processing registration','error')}
    })();
  });

  function collectForm(){
    return {
      first:form.first.value.trim(),
      last:form.last.value.trim(),
      email:form.email.value.trim(),
      password:form.password.value,
      role:form.role.value,
      org:form.org.value.trim(),
      terms:form.terms.checked
    };
  }

  function validate(d){
    if(!d.first||d.first.length<2) return 'First name required (min 2 chars)';
    if(!d.last||d.last.length<2) return 'Last name required (min 2 chars)';
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.email)) return 'Enter a valid email';
    if(d.password.length<6) return 'Password must be at least 6 characters';
    if(d.password!==form.confirm.value) return 'Passwords do not match';
    if(!d.terms) return 'You must accept the terms';
    if(d.role==='organizer' && !d.org) return 'Organization name required for organizers';
    return null;
  }

  function saveRegistration(d){
    // do not store raw passwords in production; this is demo-only
    const store=JSON.parse(localStorage.getItem('registrations')||'[]');
    // If caller provided already-sanitized object (with pwdHash/emailHash), store as-is; otherwise sanitize
    const entry = d.pwdHash || d.emailHash ? d : {first:d.first,last:d.last,email:d.email,role:d.role,org:d.org,created:new Date().toISOString()};
    store.push(entry);
    localStorage.setItem('registrations',JSON.stringify(store));
  }
});
