import { configure } from "@testing-library/react-native";

// No CI o cache de transformação do Jest começa vazio e a primeira
// renderização das telas maiores (HomeScreen) passa de 1 s, o limite padrão
// dos findBy*/waitFor; os testes falhavam esperando um campo que aparecia
// logo depois. 5 s dá folga sem mascarar uma tela que nunca aparece.
configure({ asyncUtilTimeout: 5000 });
