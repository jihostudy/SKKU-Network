# Socket Programming 
## 🔥과제 개요🔥
TA의 IPv4 server & clients와 통신하는 IPv4 client 및 server 구현

### ✏️ Steps 
1. TA의 IPv4 Server로 접근하여 정보 전달
2. TA의 IPv4 server가 IPv4 clients 생성
3. TA의 IPv4 clients가 전달받은 주소로 학생의 IPv4 server에 접근 및 random token 전달
4. 해당 토큰 값을 IPv4 connection으로 다시 학생의 client에 전달
5. 학생의 client가 TA의 IPv4 Server에 해당 random token들을 재전달 후 TA Server는 올바른 토큰인지 판단 후 최종 메세지 전달

![image](https://github.com/jihostudy/Computer_Network_Course/assets/110150963/495b1560-1661-4148-ae47-a57bd1fc3495)
   </br></br> <span style="color:red">(빨간색 : 구현해야할 사항)</span>

### ❌ 제약사항 
1. Multi clients와의 통신을 처리하기 위해서는 **concurrent server** 구현 필요
2. 컴퓨터가 사설 네트워크에 연결되어 있는 경우, 공유기 **Port Forwarding** 통한 해결
    - Port Forwarding 불가능한 경우, **Cloud Platform**(AWS, GCP, Naver Cloud etc)을 통해 Public IP 할당 받기
3. IPv4 Server가 Ipv4 Client에게 토큰을 전달하는 경우, **파일 시스템을 통한 통신 금지**
4. Extra Credit DNS 구현 시 **DNS 관련 라이브러리 사용 금지**

### 🔖 Extra Credit
IPv4 서버의 도메인 네임의 IPv4 주소를 쿼리하는 코드 구현
DNS Resolver를 구현하는 것이 아닌, DNS Resolver까지 전달하는 패킷을 구현하는 것이 목표.

---
# Project Specification
## Port Forwarding
KT 라우터를 사용하는 동안 사설 주소를 공인 IP 주소로 변경할 필요성을 깨달았습니다.<br/>
따라서 아래 그림과 같이 외부 포트와 사설 포트, 그리고 사설 IPv4 주소를 입력하여 포트 포워딩을 시도했습니다. <br/>
그러나 문제는 **WSL2에서 발생했습니다.** <br/>
WSL2는 일종의 운영체제로 작동하여 로컬 컴퓨터에서 사용하는 IP와 다른 IP가 할당됩니다.  <br/>
따라서 WSL2의 IP를 얻어 포트 포워딩을 수행해야 했습니다.  <br/>
forwarding.ps1은 PowerShell에서 관리자 권한으로 실행된 스크립트를 보여줍니다. <br/><br/>
![image](https://github.com/jihostudy/Computer_Network_Course/assets/110150963/c49a43ec-e15f-4529-b937-81803296d84d)

<br/>

**그러나 포트 포워딩 방법은 실패했습니다. 알 수 없는 이유로 연결이 불가능했는데, 이는 방화벽 문제나 메인 라우터 내의 중첩 라우터 때문일 수 있습니다.** 

## EC2 Deployment
EC2로 배포 후, 퍼블릭 ipv4 주소를 서버의 IP주소로 사용하였습니다.

Tip: vscode에 배포한 EC2 주소를 학교서버 연결하듯이 연결한다음에 개발하면 됩니다.

**DNS는 패킷 구조를 참고하여 HW2, HW3 처럼 구성하여 해결하였습니다.**


