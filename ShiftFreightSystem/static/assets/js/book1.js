document.getElementById("bookingdat").min = new Date().toISOString().split("T")[0];
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

//   function pincodeValidation(inputTxt){
    
//     var regx = /^[6][7-9][0-9]{4}$/;
//     var textField = document.getElementById("pin");
        
//     if(inputTxt.value != '' ){
//             if(inputTxt.value.match(regx)){
//                 textField.textContent = '';
//                 textField.style.color = "green";
                    
//             }else{
//                 textField.textContent = 'only valid pincode';
//                 textField.style.color = "red";
//             }  
//     }else{
//         textField.textContent = 'your input is empty';
//         textField.style.color = "red";
//     }
//   }



function pincodeValidation(inputTxt){

    const ENDPOINT = "https://api.postalpincode.in/pincode/";
    const pinStart = '670001';
    const pinEnd = '695615';

    var textField = document.getElementById("pin");

    if (textField >= pinStart && textField <= pinEnd) {
        console.log("Pincode valid.");
      } else {
        console.log("Pincode not valid. Enter a pincode existing in Kerala.");
      }
}







