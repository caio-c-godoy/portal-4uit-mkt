\
async function fetchIP(){
  try{
    // Server captures IP; this is a fallback for display if needed.
    const res = await fetch('/api/whoami').catch(()=>null);
    if(res && res.ok){ const j = await res.json(); return j.ip }
  }catch(e){}
  return 'Captured server-side';
}
function dataURLFromCanvas(canvas){
  return canvas.toDataURL('image/png');
}
function clearCanvas(canvas){
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,canvas.width,canvas.height);
}
