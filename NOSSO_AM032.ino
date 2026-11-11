/*******************************************************************************
 * AM-032 / ESP32 - Walkie-talkie ESP-NOW (NOSSA PLACA)
 * OLED SSD1306 128x64
 *
 * COMUNICAÇÃO PONTO A PONTO (P2P) E CRIPTOGRAFADA
 *  - Sem broadcast: a placa só fala com o MAC configurado em MAC_PAR
 *  - Pacotes de qualquer outro MAC são ignorados
 *  - Criptografia AES do ESP-NOW (chaves PMK e LMK iguais nas duas placas)
 *
 * SPRINT 2
 *  - MAC de cada placa no Serial e na tela
 *  - Struct de dados do ESP-NOW (Pacote)
 *  - Callbacks de envio e recebimento
 *  - Teste Ping-Pong com RTT
 *  - RSSI do link convertido em barra com porcentagem
 *  - Telemetria entre as duas placas
 *
 * SPRINT 5 (parcial)
 *  - Sincronização TX/RX para evitar colisões
 *  - Display FALANDO / ESCUTANDO (áudio simulado)
 *
 * Bateria: BATERIA --- 100k --- GPIO34 --- 100k --- GND
 * Botão PTT: GPIO26 --- [botão] --- GND
 *******************************************************************************/

#include <Wire.h>
#include "SSD1306Wire.h"
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include "esp_idf_version.h"

// ============================================================
// >>> MAC DA PLACA DO OUTRO GRUPO (TROCAR AQUI) <<<
// Exemplo: AA:BB:CC:DD:EE:FF vira {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
// ============================================================

uint8_t macPar[6] = {0x84, 0xCC, 0xA8, 0x5D, 0x0C, 0x9C};   // 84:CC:A8:5D:0C:9C

// ============================================================
// CHAVES DE CRIPTOGRAFIA (16 caracteres, iguais nas duas placas)
// ============================================================

const char CHAVE_PMK[] = "AM032_PMK_2026!!";
const char CHAVE_LMK[] = "AM032_LMK_2026!!";

// ============================================================
// CONFIGURAÇÕES DO RÁDIO (iguais nas duas placas)
// ============================================================

#define CANAL_ESPNOW 1
#define GRUPO_ID     0xA032

#define INTERVALO_PING       1000
#define INTERVALO_HEARTBEAT  200
#define TIMEOUT_ESTADO       800
#define TIMEOUT_LINK         3000
#define INTERVALO_STATS      5000

#define DEBUG_BATERIA 0

// ============================================================
// ESTRUTURA DE DADOS DO ESP-NOW (igual nas duas placas)
// ============================================================

enum TipoPacote : uint8_t
{
  PKT_PING   = 1,
  PKT_PONG   = 2,
  PKT_ESTADO = 3
};

enum EstadoRadio : uint8_t
{
  RADIO_OCIOSO    = 0,
  RADIO_FALANDO   = 1,
  RADIO_ESCUTANDO = 2
};

typedef struct __attribute__((packed))
{
  uint16_t grupo;
  uint8_t  tipo;
  uint8_t  estado;
  uint32_t seq;
  uint32_t tempoEnvio;
  float    tensaoBateria;
  uint8_t  bateria;
  int8_t   rssiVisto;
} Pacote;

typedef struct
{
  Pacote  dados;
  uint8_t mac[6];
  int8_t  rssi;
} PacoteRecebido;

QueueHandle_t filaRx;

// ============================================================
// VARIÁVEIS DO RÁDIO
// ============================================================

uint8_t macLocal[6];
String  macTexto = "";

bool pareado = false;     // peer configurado com sucesso
bool jaRecebeu = false;   // já chegou pelo menos um pacote do par

volatile uint32_t enviosOk = 0;
volatile uint32_t enviosFalha = 0;

uint32_t seqEnvio = 0;
uint32_t pingsEnviados = 0;
uint32_t pongsRecebidos = 0;

unsigned long ultimoPacoteRecebido = 0;
bool  linkAtivo = false;
float rssiFiltrado = -100;
int   linkPorcentagem = 0;
int   rttMs = -1;

float tensaoPar = 0;
int   bateriaPar = 0;
int   rssiVistoPeloPar = 0;

EstadoRadio estadoRadio = RADIO_OCIOSO;
EstadoRadio estadoRemoto = RADIO_OCIOSO;
unsigned long ultimoEstadoRemoto = 0;
unsigned long ultimoHeartbeat = 0;
bool canalOcupado = false;

// ============================================================
// OLED
// ============================================================

SSD1306Wire display(0x3C, 5, 4);

// ============================================================
// ADC DA BATERIA
// ============================================================

#define BATTERY_PIN 34
#define R1 100000.0
#define R2 100000.0
#define ADC_REFERENCE 3.3
#define ADC_MAX 4095.0

float tensaoBateria = 0;
int   porcentagemBateria = 0;

// ============================================================
// BOTÃO PTT
// ============================================================

#define BOTAO_PTT 26

bool pttPressionado = false;
bool estadoEstavelBotao = HIGH;
bool ultimaLeituraBotao = HIGH;

unsigned long ultimoDebounce = 0;
const unsigned long debounceDelay = 50;

// ============================================================
// UTILITÁRIOS
// ============================================================

String macParaTexto(const uint8_t *mac)
{
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

const char* nomeEstado(EstadoRadio e)
{
  switch (e)
  {
    case RADIO_FALANDO:   return "FALANDO";
    case RADIO_ESCUTANDO: return "ESCUTANDO";
    default:              return "OCIOSO";
  }
}

bool macVazio(const uint8_t *mac)
{
  for (int i = 0; i < 6; i++)
    if (mac[i] != 0) return false;
  return true;
}

// ============================================================
// RSSI NO CORE 2.x (só conta pacotes vindos do par)
// ============================================================

#if ESP_IDF_VERSION_MAJOR < 5
volatile int8_t rssiPromiscuo = -100;

void callbackPromiscuo(void *buf, wifi_promiscuous_pkt_type_t tipo)
{
  if (tipo != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;

  if (pkt->payload[0] != 0xD0)
    return;

  // Endereço de origem do quadro (bytes 10 a 15)
  if (memcmp(pkt->payload + 10, macPar, 6) != 0)
    return;

  rssiPromiscuo = pkt->rx_ctrl.rssi;
}
#endif

// ============================================================
// CALLBACK DE ENVIO
// ============================================================

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void aoEnviar(const wifi_tx_info_t *info, esp_now_send_status_t status)
#else
void aoEnviar(const uint8_t *mac, esp_now_send_status_t status)
#endif
{
  if (status == ESP_NOW_SEND_SUCCESS)
    enviosOk++;
  else
    enviosFalha++;
}

// ============================================================
// CALLBACK DE RECEBIMENTO
// ============================================================

void enfileirarPacote(const uint8_t *mac, const uint8_t *dados, int tamanho, int8_t rssi)
{
  // Só aceita o MAC do par
  if (memcmp(mac, macPar, 6) != 0)
    return;

  if (tamanho != sizeof(Pacote))
    return;

  PacoteRecebido r;
  memcpy(&r.dados, dados, sizeof(Pacote));

  if (r.dados.grupo != GRUPO_ID)
    return;

  memcpy(r.mac, mac, 6);
  r.rssi = rssi;

  xQueueSend(filaRx, &r, 0);
}

#if ESP_IDF_VERSION_MAJOR >= 5
void aoReceber(const esp_now_recv_info_t *info, const uint8_t *dados, int tamanho)
{
  enfileirarPacote(info->src_addr, dados, tamanho, info->rx_ctrl->rssi);
}
#else
void aoReceber(const uint8_t *mac, const uint8_t *dados, int tamanho)
{
  enfileirarPacote(mac, dados, tamanho, rssiPromiscuo);
}
#endif

// ============================================================
// PEER CRIPTOGRAFADO E ENVIO
// ============================================================

bool adicionarPeer(const uint8_t *mac)
{
  if (esp_now_is_peer_exist(mac))
    return true;

  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, mac, 6);
  peer.channel = CANAL_ESPNOW;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = true;
  memcpy(peer.lmk, CHAVE_LMK, 16);

  return esp_now_add_peer(&peer) == ESP_OK;
}

void enviarPacote(uint8_t tipo, uint32_t tempoEnvio)
{
  if (!pareado)
    return;

  Pacote p;

  p.grupo = GRUPO_ID;
  p.tipo = tipo;
  p.estado = estadoRadio;
  p.seq = ++seqEnvio;
  p.tempoEnvio = tempoEnvio;
  p.tensaoBateria = tensaoBateria;
  p.bateria = porcentagemBateria;
  p.rssiVisto = (int8_t)round(rssiFiltrado);

  // Unicast: só para o par
  if (esp_now_send(macPar, (uint8_t *)&p, sizeof(p)) != ESP_OK)
    enviosFalha++;
}

// ============================================================
// PROCESSA OS PACOTES RECEBIDOS
// ============================================================

void processarPacotes()
{
  PacoteRecebido r;

  while (xQueueReceive(filaRx, &r, 0) == pdTRUE)
  {
    unsigned long agora = millis();

    if (!jaRecebeu)
    {
      jaRecebeu = true;
      Serial.print("[PAR] Conectado com ");
      Serial.println(macParaTexto(macPar));
    }

    if (!linkAtivo)
      rssiFiltrado = r.rssi;
    else
      rssiFiltrado = (rssiFiltrado * 0.7) + (r.rssi * 0.3);

    ultimoPacoteRecebido = agora;
    linkAtivo = true;

    tensaoPar = r.dados.tensaoBateria;
    bateriaPar = r.dados.bateria;
    rssiVistoPeloPar = r.dados.rssiVisto;

    estadoRemoto = (EstadoRadio)r.dados.estado;
    ultimoEstadoRemoto = agora;

    switch (r.dados.tipo)
    {
      case PKT_PING:
        enviarPacote(PKT_PONG, r.dados.tempoEnvio);
        break;

      case PKT_PONG:
        rttMs = millis() - r.dados.tempoEnvio;
        pongsRecebidos++;

        Serial.print("[PONG] RTT ");
        Serial.print(rttMs);
        Serial.print(" ms | Par: ");
        Serial.print(tensaoPar, 2);
        Serial.print(" V ");
        Serial.print(bateriaPar);
        Serial.print("% | RSSI aqui: ");
        Serial.print(r.rssi);
        Serial.print(" dBm | RSSI la: ");
        Serial.print(rssiVistoPeloPar);
        Serial.print(" dBm | Estado par: ");
        Serial.println(nomeEstado(estadoRemoto));
        break;

      case PKT_ESTADO:
        break;
    }
  }
}

// ============================================================
// SINCRONIZAÇÃO TX/RX (HALF-DUPLEX)
// ============================================================

bool venceDesempate()
{
  return memcmp(macLocal, macPar, 6) > 0;
}

void atualizarEstadoRadio(unsigned long agora)
{
  bool remotoFalando = linkAtivo
                    && estadoRemoto == RADIO_FALANDO
                    && (agora - ultimoEstadoRemoto < TIMEOUT_ESTADO);

  EstadoRadio novo;

  if (pttPressionado)
  {
    if (!remotoFalando)
      novo = RADIO_FALANDO;
    else if (estadoRadio == RADIO_FALANDO && venceDesempate())
      novo = RADIO_FALANDO;
    else
      novo = RADIO_ESCUTANDO;
  }
  else
  {
    novo = remotoFalando ? RADIO_ESCUTANDO : RADIO_OCIOSO;
  }

  canalOcupado = pttPressionado && (novo == RADIO_ESCUTANDO);

  if (novo != estadoRadio)
  {
    if (estadoRadio == RADIO_FALANDO && novo == RADIO_ESCUTANDO)
      Serial.println("[COLISAO] Os dois falaram juntos, perdi o desempate");

    estadoRadio = novo;

    Serial.print("[ESTADO] ");
    Serial.println(nomeEstado(estadoRadio));

    enviarPacote(PKT_ESTADO, millis());
    ultimoHeartbeat = agora;
  }

  if (estadoRadio == RADIO_FALANDO
      && agora - ultimoHeartbeat >= INTERVALO_HEARTBEAT)
  {
    ultimoHeartbeat = agora;
    enviarPacote(PKT_ESTADO, millis());
  }
}

// ============================================================
// BATERIA
// ============================================================

float lerBateria()
{
  long soma = 0;

  for (int i = 0; i < 20; i++)
  {
    soma += analogRead(BATTERY_PIN);
    delay(2);
  }

  float adcAtual = soma / 20.0;
  static float adcFiltrado = 0;
  adcFiltrado = (adcFiltrado * 0.9) + (adcAtual * 0.1);
  float adc = adcFiltrado;

  float tensaoADC = (adc / ADC_MAX) * ADC_REFERENCE;
  float tensaoMedida = tensaoADC * 2.18;

#if DEBUG_BATERIA
  Serial.print("ADC medio: ");
  Serial.println(adc);
  Serial.print("Tensão ADC: ");
  Serial.println(tensaoADC, 3);
  Serial.print("Tensão bateria calculada: ");
  Serial.println(tensaoMedida, 3);
#endif

  return tensaoMedida;
}

int calcularPorcentagem(float tensao)
{
  int porcentagem;

  if (tensao >= 3.20)
    porcentagem = 100;
  else if (tensao >= 3.15)
    porcentagem = 80 + (int)((tensao - 3.15) * 400);
  else if (tensao >= 3.10)
    porcentagem = 60 + (int)((tensao - 3.10) * 400);
  else if (tensao >= 3.05)
    porcentagem = 40 + (int)((tensao - 3.05) * 400);
  else if (tensao >= 3.00)
    porcentagem = 20 + (int)((tensao - 3.00) * 400);
  else if (tensao >= 2.95)
    porcentagem = (int)((tensao - 2.95) * 400);
  else
    porcentagem = 0;

  if (porcentagem > 100) porcentagem = 100;
  if (porcentagem < 0)   porcentagem = 0;

  return porcentagem;
}

// ============================================================
// RSSI EM PORCENTAGEM (-100 dBm = 0%, -50 dBm = 100%)
// ============================================================

int calcularPorcentagemRSSI(float rssi)
{
  if (rssi <= -100) return 0;
  if (rssi >= -50)  return 100;
  return (int)(2 * (rssi + 100));
}

// ============================================================
// DESENHOS
// ============================================================

void desenharBateria(int porcentagem)
{
  int x = 90;
  int y = 1;
  int largura = 34;
  int altura = 11;

  display.drawRect(x, y, largura, altura);
  display.fillRect(x + largura, y + 3, 3, 5);

  int larguraCarga = map(porcentagem, 0, 100, 0, largura - 4);

  if (larguraCarga > 0)
    display.fillRect(x + 2, y + 2, larguraCarga, altura - 4);
}

void desenharBarraSinal(int porcentagem)
{
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.drawString(0, 12, "LINK");

  int x = 28;
  int y = 15;
  int largura = 70;
  int altura = 8;

  display.drawRect(x, y, largura, altura);

  int larguraSinal = map(porcentagem, 0, 100, 0, largura - 4);

  if (larguraSinal > 0)
    display.fillRect(x + 2, y + 2, larguraSinal, altura - 4);

  display.setTextAlignment(TEXT_ALIGN_RIGHT);
  display.drawString(127, 12, String(porcentagem) + "%");
  display.setTextAlignment(TEXT_ALIGN_LEFT);
}

void desenharMicrofone(bool transmitindo)
{
  int x = 111;
  int y = 46;

  if (transmitindo)
    display.fillRect(x, y, 8, 12);
  else
    display.drawRect(x, y, 8, 12);

  display.drawLine(x - 3, y + 6, x - 3, y + 10);
  display.drawLine(x + 10, y + 6, x + 10, y + 10);

  display.drawLine(x - 3, y + 10, x, y + 14);
  display.drawLine(x + 10, y + 10, x + 7, y + 14);
  display.drawLine(x, y + 14, x + 7, y + 14);

  display.drawLine(x + 3, y + 14, x + 3, y + 17);
  display.drawLine(x, y + 17, x + 6, y + 17);
}

float gerarNivelSimulado()
{
  float tempo = millis() / 1000.0;

  float nivel = 0.10
              + 0.48 * (0.5 + 0.5 * sin(tempo * 2.8))
              + 0.20 * (0.5 + 0.5 * sin(tempo * 6.1));

  if (random(100) < 12)
    nivel += random(15, 36) / 100.0;

  return constrain(nivel, 0.0, 1.0);
}

void desenharVUMeter(float nivel)
{
  const int xInicial = 66;
  const int yInicial = 52;
  const int larguraBarra = 4;
  const int espaco = 2;
  const int quantidade = 6;
  const int alturaMaxima = 11;

  int barrasAtivas = round(nivel * quantidade);

  for (int i = 0; i < quantidade; i++)
  {
    int x = xInicial + i * (larguraBarra + espaco);
    int altura = 3 + (i * (alturaMaxima - 3)) / (quantidade - 1);
    int y = yInicial + alturaMaxima - altura;

    if (i < barrasAtivas)
      display.fillRect(x, y, larguraBarra, altura);
    else
      display.drawRect(x, y, larguraBarra, altura);
  }
}

// ============================================================
// BOTÃO PTT COM DEBOUNCE
// ============================================================

void verificarBotaoPTT(unsigned long agora)
{
  bool leituraBotao = digitalRead(BOTAO_PTT);

  if (leituraBotao != ultimaLeituraBotao)
  {
    ultimoDebounce = agora;
    ultimaLeituraBotao = leituraBotao;
  }

  if ((agora - ultimoDebounce) > debounceDelay)
  {
    if (leituraBotao != estadoEstavelBotao)
    {
      estadoEstavelBotao = leituraBotao;
      pttPressionado = (estadoEstavelBotao == LOW);

      Serial.print("PTT: ");
      Serial.println(pttPressionado ? "PRESSIONADO" : "SOLTO");
    }
  }
}

// ============================================================
// TELA
// ============================================================

void desenharTela()
{
  display.clear();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(ArialMT_Plain_10);

  // Linha 1: bateria local
  display.drawString(
    0, 0,
    String(tensaoBateria, 2) + " V  " + String(porcentagemBateria) + "%"
  );
  desenharBateria(porcentagemBateria);

  // Linha 2: sinal do link
  desenharBarraSinal(linkPorcentagem);

  // Linha 3: telemetria do par
  if (!jaRecebeu)
  {
    display.drawString(0, 24, "AGUARDANDO PAR...");
  }
  else if (!linkAtivo)
  {
    display.drawString(0, 24, "PAR PERDIDO");
  }
  else
  {
    String rtt = (rttMs >= 0) ? String(rttMs) + "ms" : "--ms";
    display.drawString(
      0, 24,
      "PAR " + String(tensaoPar, 2) + "V " + String(bateriaPar) + "% " + rtt
    );
  }

  // Linha 4: MAC desta placa
  display.drawString(0, 36, macTexto);

  // Linha 5: estado do rádio
  switch (estadoRadio)
  {
    case RADIO_FALANDO:
      display.drawString(0, 50, "FALANDO");
      desenharVUMeter(gerarNivelSimulado());
      break;

    case RADIO_ESCUTANDO:
      display.drawString(0, 50, canalOcupado ? "OCUPADO" : "ESCUTANDO");
      desenharVUMeter(gerarNivelSimulado());
      break;

    default:
      display.drawString(0, 50, "SEGURE P/ FALAR");
      break;
  }

  desenharMicrofone(estadoRadio == RADIO_FALANDO);

  display.display();
}

void mostrarErro(const char *linha1, const char *linha2)
{
  Serial.print("ERRO: ");
  Serial.print(linha1);
  Serial.print(" ");
  Serial.println(linha2);

  display.clear();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(ArialMT_Plain_10);
  display.drawString(0, 0, linha1);
  display.drawString(0, 14, linha2);
  display.drawString(0, 36, macTexto);
  display.display();

  while (true)
    delay(1000);
}

// ============================================================
// SETUP
// ============================================================

void setup()
{
  Serial.begin(115200);
  delay(200);

  display.init();

  // display.flipScreenVertically();

  display.clear();
  display.setFont(ArialMT_Plain_10);
  display.drawString(0, 0, "Iniciando ESP-NOW...");
  display.display();

  pinMode(BATTERY_PIN, INPUT);
  analogReadResolution(12);
  analogSetPinAttenuation(BATTERY_PIN, ADC_11db);

  pinMode(BOTAO_PTT, INPUT_PULLUP);

  filaRx = xQueueCreate(16, sizeof(PacoteRecebido));

  // Wi-Fi em modo estação, sem roteador, canal fixo
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(CANAL_ESPNOW, WIFI_SECOND_CHAN_NONE);

#if ESP_IDF_VERSION_MAJOR < 5
  esp_wifi_set_promiscuous_rx_cb(callbackPromiscuo);
#else
  esp_wifi_set_promiscuous(false);
#endif

  esp_wifi_get_mac(WIFI_IF_STA, macLocal);
  macTexto = macParaTexto(macLocal);

  Serial.println();
  Serial.println("==============================");
  Serial.print("MAC desta placa: ");
  Serial.println(macTexto);
  Serial.print("MAC do par:      ");
  Serial.println(macParaTexto(macPar));
  Serial.println("==============================");

  if (macVazio(macPar))
    mostrarErro("FALTA O MAC DO PAR", "Edite macPar[6]");

  if (memcmp(macPar, macLocal, 6) == 0)
    mostrarErro("MAC DO PAR ERRADO", "E o MAC desta placa");

  if (esp_now_init() != ESP_OK)
    mostrarErro("ERRO ESP-NOW", "Falha ao iniciar");

  // Chave mestra da criptografia
  esp_now_set_pmk((const uint8_t *)CHAVE_PMK);

  esp_now_register_send_cb(aoEnviar);
  esp_now_register_recv_cb(aoReceber);

  // Peer único e criptografado
  if (!adicionarPeer(macPar))
    mostrarErro("ERRO AO ADICIONAR", "O PAR NO ESP-NOW");

  pareado = true;

  Serial.println("ESP-NOW P2P criptografado pronto. Aguardando par...");
}

// ============================================================
// LOOP
// ============================================================

void loop()
{
  static unsigned long ultimaBateria = 0;
  static unsigned long ultimaTela = 0;
  static unsigned long ultimoPing = 0;
  static unsigned long ultimaStats = 0;

  unsigned long agora = millis();

  verificarBotaoPTT(agora);
  processarPacotes();

  linkAtivo = jaRecebeu && (agora - ultimoPacoteRecebido < TIMEOUT_LINK);
  linkPorcentagem = linkAtivo ? calcularPorcentagemRSSI(rssiFiltrado) : 0;

  atualizarEstadoRadio(agora);

  if (agora - ultimaBateria >= 500)
  {
    ultimaBateria = agora;
    tensaoBateria = lerBateria();
    porcentagemBateria = calcularPorcentagem(tensaoBateria);
  }

  if (agora - ultimoPing >= INTERVALO_PING)
  {
    ultimoPing = agora;
    enviarPacote(PKT_PING, millis());
    pingsEnviados++;
  }

  if (agora - ultimaStats >= INTERVALO_STATS)
  {
    ultimaStats = agora;

    int perda = 0;
    if (pingsEnviados > 0)
      perda = 100 - (int)((pongsRecebidos * 100) / pingsEnviados);

    Serial.print("[STATS] Bateria: ");
    Serial.print(tensaoBateria, 2);
    Serial.print(" V ");
    Serial.print(porcentagemBateria);
    Serial.print("% | Envios OK: ");
    Serial.print(enviosOk);
    Serial.print(" | Falhas: ");
    Serial.print(enviosFalha);
    Serial.print(" | Pings: ");
    Serial.print(pingsEnviados);
    Serial.print(" | Pongs: ");
    Serial.print(pongsRecebidos);
    Serial.print(" | Perda: ");
    Serial.print(perda);
    Serial.print("% | Link: ");
    Serial.print(linkPorcentagem);
    Serial.println("%");
  }

  if (agora - ultimaTela >= 50)
  {
    ultimaTela = agora;
    desenharTela();
  }
}
