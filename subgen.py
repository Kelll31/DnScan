import numpy as np
import sys
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Embedding
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import to_categorical
from tqdm import tqdm  # Для отображения прогресса

# Проверка на наличие флага -nm
retrain_model = '-nm' in sys.argv

# Загрузка данных
with open('subdomains-10000.txt', 'r') as file:
    subdomains = file.readlines()

# Предобработка данных
tokenizer = Tokenizer(char_level=True)
tokenizer.fit_on_texts(subdomains)
sequences = tokenizer.texts_to_sequences(subdomains)
max_sequence_len = max([len(seq) for seq in sequences])
sequences = pad_sequences(sequences, maxlen=max_sequence_len, padding='post')

# Подготовка данных для обучения
X = sequences[:, :-1]
y = sequences[:, 1:]
y = to_categorical(y, num_classes=len(tokenizer.word_index) + 1)

# Загрузка или создание модели
if not retrain_model:
    try:
        model = load_model('subdomain_generator.keras')
        print("Модель загружена из файла.")
    except (OSError, IOError):
        print("Файл модели не найден, обучение новой модели.")
        retrain_model = True

if retrain_model:
    # Создание модели
    model = Sequential()
    model.add(Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=50, input_length=max_sequence_len-1))
    model.add(LSTM(100, return_sequences=True))
    model.add(Dense(len(tokenizer.word_index) + 1, activation='softmax'))

    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

    # Обучение модели
    model.fit(X, y, epochs=10, batch_size=64)

    # Сохранение модели в формате .keras
    model.save('subdomain_generator.keras')
    print("Модель сохранена в файл.")

# Генерация новых поддоменов
def generate_subdomain(seed_text, next_chars=50):
    for _ in range(next_chars):
        token_list = tokenizer.texts_to_sequences([seed_text])[0]
        token_list = pad_sequences([token_list], maxlen=max_sequence_len-1, padding='post')
        predicted = model.predict(token_list, verbose=0)
        predicted_char_index = np.argmax(predicted, axis=-1)[0, -1]
        output_char = tokenizer.index_word.get(predicted_char_index, '')
        seed_text += output_char
        if output_char == '\n':
            break
    return seed_text.strip()

# Генерация и сохранение новых поддоменов с отображением прогресса
new_subdomains = [generate_subdomain('') for _ in tqdm(range(1000), desc="Генерация поддоменов")]
with open('subdomains-extended.txt', 'w') as file:
    for subdomain in new_subdomains:
        file.write(subdomain + '\n')