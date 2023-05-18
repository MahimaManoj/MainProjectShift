function nameValidate(inputTxt){
    
    var regx = /^[a-zA-Z]+ [a-zA-Z]+$/;
    var textField = document.getElementById("nameError");
      
    if(inputTxt.value != '' ){
        if(inputTxt.value.length >= 4){
            if(inputTxt.value.match(regx)){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'only characters allowded';
                textField.style.color = "red";
            }  
        }else{
            textField.textContent = 'your input mut me more than two chracters';
            textField.style.color = "red";
        }   
    }
    else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }

  function emailValidation(inputTxt){
    // ^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$
    var regx = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    // var regx = /^([\w-\.]+@(?!gmail.com)(?!yahoo.com)(?!hotmail.com)([\w-]+\.)+[\w-]{2,4})?$/;
    var textField = document.getElementById("mail");
        
    if(inputTxt.value != '' ){
        if(inputTxt.value.match(regx)){
            textField.textContent = '';
            textField.style.color = "green";
        }else{
            textField.textContent = 'email is not valid!!!';
            textField.style.color = "red";
        }  
    }else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }

  function phoneValidation(inputTxt){
    
    var regx = /^[6-9][0-9]{9}$/;
    var textField = document.getElementById("pho");
        
    if(inputTxt.value != '' ){
        if(inputTxt.value.match(regx)){
            textField.textContent = '';
            textField.style.color = "green";        
            }else{
                textField.textContent = '**not valid phone number';
                textField.style.color = "red";
            }  
    }else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }

  function passwordValidation(inputTxt){
    
    var regx = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{5,}/;
    var textField = document.getElementById("pass");
        
    if(inputTxt.value != '' ){
            if(inputTxt.value.match(regx)){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'Must contain at least one number and one uppercase and lowercase letter and aleast 5 characters';
                textField.style.color = "red";
            }    
    }else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
}

function confirmpasswordValidation(inputTxt){
    
    var regx =  document.getElementById("pwd1").value;
    var regy =  document.getElementById("pwd2").value;
    var textField = document.getElementById("pass");
    var textField = document.getElementById("confirmpass");
        
    if(inputTxt.value != '' ){    
            if(regx == regy){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'not match';
                textField.style.color = "red";
            }  
        }else{
            textField.textContent = '';
            textField.style.color = "red";
        }  
}

function cityValidate(inputTxt){
    
    var regx = /^[a-zA-Z]+ [a-zA-Z]+$/;
    var textField = document.getElementById("city");
      
    if(inputTxt.value != '' ){
        if(inputTxt.value.length >= 4){
            if(inputTxt.value.match(regx)){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'only characters allowded';
                textField.style.color = "red";
            }  
        }else{
            textField.textContent = 'your input mut me more than two chracters';
            textField.style.color = "red";
        }   
    }
    else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }

function addressValidation(inputTxt){
    
    var regx = /^[a-zA-Z\s,()'-]*$/;
    var textField = document.getElementById("addr");
        
    if(inputTxt.value != '' ){
    
        if(inputTxt.value.length >= 5){
        
            if(inputTxt.value.match(regx)){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'only characters allowded';
                textField.style.color = "red";
            }  
        }else{
            textField.textContent = 'your input must me more chracters';
            textField.style.color = "red";
        }   
    }else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }

  function pincodeValidation(inputTxt){
    
    var regx = /^[6][0-9]{5}$/;
    var textField = document.getElementById("pin");
        
    if(inputTxt.value != '' ){
            if(inputTxt.value.match(regx)){
                textField.textContent = '';
                textField.style.color = "green";
                    
            }else{
                textField.textContent = 'only valid pincode';
                textField.style.color = "red";
            }  
    }else{
        textField.textContent = 'your input is empty';
        textField.style.color = "red";
    }
  }
