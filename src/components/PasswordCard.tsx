import { Feather } from "@expo/vector-icons";
import * as Clipboard from "expo-clipboard";
import { memo, useEffect, useRef, useState } from "react";
import {
  Alert,
  Animated,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";

import { authenticateVaultAccess } from "../utils/biometricAuth";
import { SENSITIVE_TEXT_INPUT_PROPS } from "../utils/sensitiveInput";

const ICON_SIZE = 18;

const CLIPBOARD_CLEAR_MS = 30000;

export interface PasswordCardItem {
  id: string;
  title: string;
  username: string;
  password: string;
}

export interface PasswordCardTheme {
  card: string;
  border: string;
  text: string;
  textMuted: string;
  accent: string;
  accentSoft: string;
  secondaryButton: string;
  secondaryText: string;
  dangerSoft: string;
  dangerText: string;
  successSoft: string;
  successText: string;
}

const defaultTheme: PasswordCardTheme = {
  card: "#FFFFFF",
  border: "#D7E2F3",
  text: "#0E1B2E",
  textMuted: "#66798F",
  accent: "#215FCC",
  accentSoft: "#DCE8FB",
  secondaryButton: "#E6EEFC",
  secondaryText: "#183C7A",
  dangerSoft: "#FBEAE3",
  dangerText: "#B14226",
  successSoft: "#E8F3EA",
  successText: "#2F7A4C",
};

const MONO_FONT = Platform.select({
  ios: "Menlo",
  android: "monospace",
  default: "monospace",
});

export interface PasswordCardProps {
  item: PasswordCardItem;
  onDelete: (id: string) => void;
  onUpdate: (
    id: string,
    updates: { title: string; username: string; password: string },
  ) => void;
  index?: number;
  theme?: PasswordCardTheme;
}

function PasswordCard({
  item,
  onDelete,
  onUpdate,
  index = 0,
  theme = defaultTheme,
}: PasswordCardProps) {
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState(item.title);
  const [editUsername, setEditUsername] = useState(item.username);
  const [editPassword, setEditPassword] = useState(item.password);
  const [appear] = useState(() => new Animated.Value(0));
  const clipboardTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    Animated.timing(appear, {
      toValue: 1,
      duration: 380,
      delay: Math.min(index * 70, 420),
      useNativeDriver: true,
    }).start();
  }, [appear, index]);

  useEffect(() => {
    return () => {
      if (clipboardTimerRef.current) {
        clearTimeout(clipboardTimerRef.current);
      }
    };
  }, []);

  const authenticateSensitiveAction = async (): Promise<boolean> => {
    try {
      const authResult = await authenticateVaultAccess();

      if (!authResult.success) {
        if ("error" in authResult && authResult.error === "user_cancel") {
          return false;
        }

        Alert.alert(
          "Autenticacao indisponivel",
          "Ative Face ID, Touch ID ou uma senha de bloqueio no aparelho para acessar o cofre.",
        );
        return false;
      }

      return true;
    } catch {
      Alert.alert(
        "Falha na autenticacao",
        "Nao foi possivel validar sua identidade.",
      );
      return false;
    }
  };

  const handleCopy = async () => {
    const isAuthorized = await authenticateSensitiveAction();
    if (!isAuthorized) return;

    try {
      await Clipboard.setStringAsync(item.password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);

      if (clipboardTimerRef.current) {
        clearTimeout(clipboardTimerRef.current);
      }

      clipboardTimerRef.current = setTimeout(async () => {
        try {
          const currentClipboard = await Clipboard.getStringAsync();
          if (currentClipboard === item.password) {
            await Clipboard.setStringAsync("");
          }
        } catch {
          // Nao interrompe o fluxo se a limpeza automatica falhar.
        }
      }, CLIPBOARD_CLEAR_MS);
    } catch (_error) {
      Alert.alert(
        "Falha ao copiar",
        "Nao foi possivel copiar a senha no momento.",
      );
    }
  };

  const handleSaveEdit = () => {
    if (!editTitle.trim() || !editUsername.trim() || !editPassword.trim()) {
      Alert.alert("Campos obrigatorios", "Preencha titulo, usuario e senha.");
      return;
    }

    onUpdate(item.id, {
      title: editTitle.trim(),
      username: editUsername.trim(),
      password: editPassword,
    });
    setIsEditing(false);
  };

  const handleCancelEdit = () => {
    setEditTitle(item.title);
    setEditUsername(item.username);
    setEditPassword(item.password);
    setIsEditing(false);
  };

  const handleTogglePassword = async () => {
    const isAuthorized = await authenticateSensitiveAction();
    if (!isAuthorized) return;

    setShowPassword((prev) => !prev);
  };

  const handleStartEdit = async () => {
    const isAuthorized = await authenticateSensitiveAction();
    if (!isAuthorized) return;

    setEditTitle(item.title);
    setEditUsername(item.username);
    setEditPassword(item.password);
    setIsEditing(true);
  };

  const handleDelete = async () => {
    const isAuthorized = await authenticateSensitiveAction();
    if (!isAuthorized) return;

    onDelete(item.id);
  };

  return (
    <Animated.View
      style={[
        styles.card,
        {
          backgroundColor: theme.card,
          borderColor: theme.border,
          opacity: appear,
          transform: [
            {
              translateY: appear.interpolate({
                inputRange: [0, 1],
                outputRange: [18, 0],
              }),
            },
          ],
        },
      ]}
    >
      <View style={styles.headerRow}>
        <Text style={[styles.title, { color: theme.text }]}>{item.title}</Text>
      </View>

      {isEditing ? (
        <View style={styles.editWrapper}>
          <TextInput
            value={editTitle}
            onChangeText={setEditTitle}
            placeholder="Titulo"
            placeholderTextColor={theme.textMuted}
            {...SENSITIVE_TEXT_INPUT_PROPS}
            style={[
              styles.editInput,
              {
                backgroundColor: theme.card,
                borderColor: theme.border,
                color: theme.text,
              },
            ]}
          />
          <TextInput
            value={editUsername}
            onChangeText={setEditUsername}
            placeholder="Usuario"
            placeholderTextColor={theme.textMuted}
            {...SENSITIVE_TEXT_INPUT_PROPS}
            style={[
              styles.editInput,
              {
                backgroundColor: theme.card,
                borderColor: theme.border,
                color: theme.text,
              },
            ]}
          />
          <TextInput
            value={editPassword}
            onChangeText={setEditPassword}
            placeholder="Senha"
            placeholderTextColor={theme.textMuted}
            {...SENSITIVE_TEXT_INPUT_PROPS}
            secureTextEntry
            style={[
              styles.editInput,
              {
                backgroundColor: theme.card,
                borderColor: theme.border,
                color: theme.text,
              },
            ]}
          />
        </View>
      ) : (
        <>
          <View style={styles.infoBlock}>
            <Text style={[styles.label, { color: theme.textMuted }]}>
              Usuario
            </Text>
            <Text style={[styles.value, { color: theme.text }]}>
              {item.username}
            </Text>
          </View>

          <View style={styles.infoBlock}>
            <Text style={[styles.label, { color: theme.textMuted }]}>
              Senha
            </Text>
            <Text
              style={[styles.value, styles.valueMono, { color: theme.text }]}
            >
              {showPassword ? item.password : "••••••••••"}
            </Text>
          </View>
        </>
      )}

      <View style={styles.actions}>
        {isEditing ? (
          <>
            <Pressable
              style={({ pressed }) => [
                styles.secondaryButton,
                { backgroundColor: theme.secondaryButton },
                pressed && styles.pressed,
              ]}
              onPress={handleCancelEdit}
            >
              <Text
                style={[styles.secondaryText, { color: theme.secondaryText }]}
              >
                Cancelar
              </Text>
            </Pressable>
            <Pressable
              style={({ pressed }) => [
                styles.secondaryButton,
                { backgroundColor: theme.successSoft },
                pressed && styles.pressed,
              ]}
              onPress={handleSaveEdit}
            >
              <Text
                style={[styles.secondaryText, { color: theme.successText }]}
              >
                Salvar edicao
              </Text>
            </Pressable>
          </>
        ) : (
          <>
            <Pressable
              style={({ pressed }) => [
                styles.iconButton,
                { backgroundColor: theme.secondaryButton },
                pressed && styles.pressed,
              ]}
              onPress={handleTogglePassword}
              accessibilityRole="button"
              accessibilityLabel={
                showPassword ? "Ocultar senha" : "Mostrar senha"
              }
            >
              <Feather
                name={showPassword ? "eye-off" : "eye"}
                size={ICON_SIZE}
                color={theme.secondaryText}
              />
            </Pressable>

            <Pressable
              style={({ pressed }) => [
                styles.iconButton,
                copied
                  ? { backgroundColor: theme.successSoft }
                  : { backgroundColor: theme.secondaryButton },
                pressed && styles.pressed,
              ]}
              onPress={handleCopy}
              accessibilityRole="button"
              accessibilityLabel={copied ? "Senha copiada" : "Copiar senha"}
            >
              <Feather
                name={copied ? "check" : "copy"}
                size={ICON_SIZE}
                color={copied ? theme.successText : theme.secondaryText}
              />
            </Pressable>

            <Pressable
              style={({ pressed }) => [
                styles.iconButton,
                { backgroundColor: theme.accentSoft },
                pressed && styles.pressed,
              ]}
              onPress={handleStartEdit}
              accessibilityRole="button"
              accessibilityLabel="Editar credencial"
            >
              <Feather name="edit-2" size={ICON_SIZE} color={theme.accent} />
            </Pressable>

            <Pressable
              style={({ pressed }) => [
                styles.iconButton,
                { backgroundColor: theme.dangerSoft },
                pressed && styles.pressed,
              ]}
              onPress={handleDelete}
              accessibilityRole="button"
              accessibilityLabel="Excluir credencial"
            >
              <Feather
                name="trash-2"
                size={ICON_SIZE}
                color={theme.dangerText}
              />
            </Pressable>
          </>
        )}
      </View>
    </Animated.View>
  );
}

export default memo(PasswordCard);

const styles = StyleSheet.create({
  card: {
    padding: 16,
    borderRadius: 18,
    marginBottom: 12,
    borderWidth: 1,
    elevation: 3,
  },
  headerRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  title: {
    fontWeight: "700",
    fontSize: 18,
  },
  infoBlock: {
    marginBottom: 10,
  },
  editWrapper: {
    gap: 8,
    marginBottom: 10,
  },
  editInput: {
    borderWidth: 1,
    borderRadius: 10,
    paddingVertical: 10,
    paddingHorizontal: 12,
    fontSize: 14,
  },
  label: {
    fontSize: 12,
    marginBottom: 3,
  },
  value: {
    fontSize: 15,
    fontWeight: "600",
  },
  valueMono: {
    fontFamily: MONO_FONT,
    letterSpacing: 0.5,
  },
  actions: {
    marginTop: 6,
    flexDirection: "row",
    gap: 10,
  },
  secondaryButton: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: 10,
    alignItems: "center",
  },
  secondaryText: {
    fontWeight: "700",
    fontSize: 13,
  },
  iconButton: {
    flex: 1,
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
  },
  pressed: {
    opacity: 0.9,
    transform: [{ scale: 0.98 }],
  },
});
